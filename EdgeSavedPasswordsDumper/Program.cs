using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;



class Program
{
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_READ = 0x0010;
    const uint TOKEN_QUERY = 0x0008;
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_GUARD = 0x100;
    const uint PAGE_NOACCESS = 0x01;

    const int ChunkSize = 1024 * 1024;
    const int OverlapChars = 4096;
    const long MaxRegionBytes = 64L * 1024L * 1024L;

    static readonly Regex CredentialPattern = new Regex(
        @"[a-zA-Z]https?\x20([a-zA-ZæøåÆØÅ0-9\\-_\.@\?]{3,20})\x20([a-zA-ZæøåÆØÅ0-9#!@#\$%\^&\*\(\)_\-\+=\{\}\[\]:;<>\?/~\s]{6,40})\x20\x00",
        RegexOptions.Compiled);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    sealed class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeKernelHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern SafeKernelHandle OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(SafeKernelHandle ProcessHandle, uint DesiredAccess, out SafeKernelHandle TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(SafeKernelHandle hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern int VirtualQueryEx(SafeKernelHandle hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    class ProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Owner { get; set; }
        public string ExecutablePath { get; set; }
        public string EdgeVersion { get; set; }
        public int SessionId { get; set; }
    }

    class AuditStats
    {
        public int DiscoveredRootProcesses { get; set; }
        public int ScannedProcesses { get; set; }
        public int SkippedDifferentUser { get; set; }
        public int SkippedDifferentSession { get; set; }
        public int OpenFailures { get; set; }
        public int QueryFailures { get; set; }
        public int ReadFailures { get; set; }
        public int ChunksRead { get; set; }
        public int RegionsSkippedLarge { get; set; }
        public int RegionsSkippedUnreadable { get; set; }
        public long BytesRead { get; set; }
        public int Findings { get; set; }
    }

    static string GetProcessOwnerFromToken(int pid)
    {
        using (SafeKernelHandle hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid))
        {
            if (hProcess == null || hProcess.IsInvalid)
                return "UNKNOWN";

            SafeKernelHandle hToken;
            if (!OpenProcessToken(hProcess, TOKEN_QUERY, out hToken))
                return "UNKNOWN";

            using (hToken)
            {
                if (hToken == null || hToken.IsInvalid)
                    return "UNKNOWN";

                try
                {
                    using (WindowsIdentity wi = new WindowsIdentity(hToken.DangerousGetHandle()))
                    {
                        return wi.Name ?? "UNKNOWN";
                    }
                }
                catch
                {
                    return "UNKNOWN";
                }
            }
        }
    }

    static string GetEdgeVersion(string executablePath)
    {
        if (String.IsNullOrEmpty(executablePath) || !File.Exists(executablePath))
            return "UNKNOWN";

        try
        {
            FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(executablePath);
            if (!String.IsNullOrEmpty(versionInfo.ProductVersion))
                return versionInfo.ProductVersion;
            if (!String.IsNullOrEmpty(versionInfo.FileVersion))
                return versionInfo.FileVersion;
        }
        catch
        {
        }

        return "UNKNOWN";
    }

    static string MaskPassword(string value)
    {
        if (String.IsNullOrEmpty(value))
            return String.Empty;

        if (value.Length <= 2)
            return new string('*', value.Length);

        return value[0] + new string('*', value.Length - 2) + value[value.Length - 1];
    }

    static string MaskIdentifier(string value)
    {
        if (String.IsNullOrEmpty(value))
            return "<empty>";

        if (value.Length <= 2)
            return new string('*', value.Length);

        return value[0] + new string('*', Math.Min(10, value.Length - 2)) + value[value.Length - 1];
    }

    static string HashForDedup(string value)
    {
        using (SHA256 sha = SHA256.Create())
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value ?? String.Empty);
            byte[] hash = sha.ComputeHash(bytes);
            StringBuilder sb = new StringBuilder(hash.Length * 2);

            for (int i = 0; i < hash.Length; i++)
                sb.Append(hash[i].ToString("x2"));

            Array.Clear(bytes, 0, bytes.Length);
            Array.Clear(hash, 0, hash.Length);
            return sb.ToString();
        }
    }

    static bool IsCurrentUser(string owner, string currentUser)
    {
        return String.Equals(owner, currentUser, StringComparison.OrdinalIgnoreCase);
    }

    static bool IsReadableRegion(MEMORY_BASIC_INFORMATION memInfo)
    {
        uint protect = memInfo.Protect & 0xff;
        return memInfo.State == MEM_COMMIT
            && protect == PAGE_READWRITE
            && (memInfo.Protect & PAGE_GUARD) == 0
            && (memInfo.Protect & PAGE_NOACCESS) == 0;
    }

    static string SafeSessionName()
    {
        string sessionName = Environment.GetEnvironmentVariable("SESSIONNAME");
        if (String.IsNullOrEmpty(sessionName))
            return "UNKNOWN";

        return sessionName;
    }

    static string SanitizeLocation(string rawValue, string protocol)
    {
        if (String.IsNullOrEmpty(rawValue))
            return "unknown";

        string cleaned = rawValue.Trim('\0', ' ', '\t', '\r', '\n');
        if (cleaned.Length == 0)
            return "unknown";

        string candidate = cleaned;
        if (!candidate.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !candidate.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            string scheme = String.IsNullOrEmpty(protocol) ? "https" : protocol;
            candidate = scheme + "://" + candidate.TrimStart('/', '\\');
        }

        try
        {
            Uri uri;
            if (Uri.TryCreate(candidate, UriKind.Absolute, out uri) && !String.IsNullOrEmpty(uri.Host))
                return uri.Host;
        }
        catch
        {
        }

        int end = cleaned.IndexOfAny(new char[] { '/', '?', '#', ' ', '\0' });
        string hostOnly = end >= 0 ? cleaned.Substring(0, end) : cleaned;
        if (hostOnly.Length > 120)
            hostOnly = hostOnly.Substring(0, 120);

        return hostOnly.Length == 0 ? "unknown" : hostOnly;
    }

    static bool ConfirmAudit()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[!] Audit scope and handling");
        Console.ResetColor();
        Console.WriteLine("    - Only Edge processes owned by the current Windows user and current session are scanned.");
        Console.WriteLine("    - Password values are never printed in clear text; only first and last characters are shown.");
        Console.WriteLine("    - Full URLs are not printed; only a sanitized host/domain is shown when available.");
        Console.WriteLine("    - This should be run only on systems and accounts you are authorized to audit.");
        Console.Write("\nType AUDIT to continue: ");

        string confirmation = Console.ReadLine();
        return String.Equals(confirmation, "AUDIT", StringComparison.Ordinal);
    }

    static List<ProcessInfo> GetRootEdgeProcesses()
    {
        List<ProcessInfo> processList = new List<ProcessInfo>();

        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
            "SELECT ProcessId, Name, ParentProcessId, ExecutablePath, SessionId FROM Win32_Process WHERE Name='msedge.exe'"))
        {
            using (ManagementObjectCollection results = searcher.Get())
            {
                foreach (ManagementObject mo in results)
                {
                    using (mo)
                    {
                        int pid = Convert.ToInt32(mo["ProcessId"]);
                        int parentPid = Convert.ToInt32(mo["ParentProcessId"]);

                        bool skip = false;
                        try
                        {
                            using (Process parent = Process.GetProcessById(parentPid))
                            {
                                if (parent.ProcessName.Equals("msedge", StringComparison.OrdinalIgnoreCase))
                                    skip = true;
                            }
                        }
                        catch
                        {
                            // Parent may have exited; treat this as a root process candidate.
                        }

                        if (skip)
                            continue;

                        string executablePath = mo["ExecutablePath"] == null ? String.Empty : mo["ExecutablePath"].ToString();
                        int sessionId = mo["SessionId"] == null ? -1 : Convert.ToInt32(mo["SessionId"]);

                        processList.Add(new ProcessInfo
                        {
                            Id = pid,
                            Name = mo["Name"] == null ? "msedge.exe" : mo["Name"].ToString(),
                            Owner = GetProcessOwnerFromToken(pid),
                            ExecutablePath = executablePath,
                            EdgeVersion = GetEdgeVersion(executablePath),
                            SessionId = sessionId
                        });
                    }
                }
            }
        }

        return processList;
    }

    static void ScanProcess(ProcessInfo proc, HashSet<string> seenHashes, AuditStats stats)
    {
        using (SafeKernelHandle processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id))
        {
            if (processHandle == null || processHandle.IsInvalid)
            {
                stats.OpenFailures++;
                Console.WriteLine("  Could not open process for audit. Error: " + Marshal.GetLastWin32Error());
                return;
            }

            stats.ScannedProcesses++;

            IntPtr address = IntPtr.Zero;
            MEMORY_BASIC_INFORMATION memInfo;

            bool queriedAnyRegion = false;

            while (VirtualQueryEx(processHandle, address, out memInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
            {
                queriedAnyRegion = true;
                long baseAddress = memInfo.BaseAddress.ToInt64();
                long regionSize = memInfo.RegionSize.ToInt64();
                if (regionSize <= 0)
                    break;

                if (!IsReadableRegion(memInfo))
                {
                    stats.RegionsSkippedUnreadable++;
                }
                else if (regionSize > MaxRegionBytes)
                {
                    stats.RegionsSkippedLarge++;
                }
                else
                {
                    ScanRegion(processHandle, baseAddress, regionSize, proc, seenHashes, stats);
                }

                long nextAddress = baseAddress + regionSize;
                if (nextAddress <= address.ToInt64())
                    break;

                address = new IntPtr(nextAddress);
            }

            if (!queriedAnyRegion)
                stats.QueryFailures++;
        }
    }

    static void ScanRegion(SafeKernelHandle processHandle, long baseAddress, long regionSize, ProcessInfo proc, HashSet<string> seenHashes, AuditStats stats)
    {
        long offset = 0;
        string carry = String.Empty;

        while (offset < regionSize)
        {
            int toRead = (int)Math.Min(ChunkSize, regionSize - offset);
            byte[] buffer = new byte[toRead];
            IntPtr bytesRead;

            bool readOk = ReadProcessMemory(processHandle, new IntPtr(baseAddress + offset), buffer, toRead, out bytesRead);
            if (!readOk)
            {
                stats.ReadFailures++;
                offset += toRead;
                continue;
            }

            int readCount = (int)Math.Min(bytesRead.ToInt64(), toRead);
            if (readCount > 0)
            {
                stats.ChunksRead++;
                stats.BytesRead += readCount;

                string text = carry + Encoding.UTF8.GetString(buffer, 0, readCount);
                AuditText(text, proc, seenHashes, stats);

                carry = text.Length > OverlapChars
                    ? text.Substring(text.Length - OverlapChars)
                    : text;
            }

            Array.Clear(buffer, 0, buffer.Length);
            offset += toRead;
        }
    }

    static void AuditText(string text, ProcessInfo proc, HashSet<string> seenHashes, AuditStats stats)
    {
        MatchCollection matches = CredentialPattern.Matches(text);

        foreach (Match match in matches)
        {
            string username = match.Groups[1].Value;
            string password = match.Groups[2].Value;
            string maskedPassword = MaskPassword(password);
            bool showedWithLocation = false;

            string urlPattern = @"\x00\x00\x00([A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)(https?)\x20"
                + Regex.Escape(username)
                + " "
                + Regex.Escape(password);

            foreach (Match urlMatch in Regex.Matches(text, urlPattern))
            {
                string location = SanitizeLocation(urlMatch.Groups[1].Value, urlMatch.Groups[2].Value);
                string dedupKey = HashForDedup(username + "\0" + password + "\0" + location);

                if (!seenHashes.Contains(dedupKey))
                {
                    seenHashes.Add(dedupKey);
                    stats.Findings++;
                    Console.WriteLine("  Risk finding #{0}: account={1} password={2} host={3}",
                        stats.Findings,
                        MaskIdentifier(username),
                        maskedPassword,
                        location);
                }

                showedWithLocation = true;
            }

            if (!showedWithLocation)
            {
                string dedupKey = HashForDedup(username + "\0" + password + "\0unknown");

                if (!seenHashes.Contains(dedupKey))
                {
                    seenHashes.Add(dedupKey);
                    stats.Findings++;
                    Console.WriteLine("  Risk finding #{0}: account={1} password={2} host=unknown",
                        stats.Findings,
                        MaskIdentifier(username),
                        maskedPassword);
                }
            }

            username = null;
            password = null;
        }
    }

    static void PrintSummary(AuditStats stats)
    {
        Console.WriteLine();
        Console.WriteLine("Audit summary");
        Console.WriteLine("-------------");
        Console.WriteLine("Root Edge processes discovered: {0}", stats.DiscoveredRootProcesses);
        Console.WriteLine("Processes scanned: {0}", stats.ScannedProcesses);
        Console.WriteLine("Skipped - different user: {0}", stats.SkippedDifferentUser);
        Console.WriteLine("Skipped - different session: {0}", stats.SkippedDifferentSession);
        Console.WriteLine("Findings: {0}", stats.Findings);
        Console.WriteLine("Memory chunks read: {0}", stats.ChunksRead);
        Console.WriteLine("Large regions skipped: {0}", stats.RegionsSkippedLarge);
        Console.WriteLine("Unreadable regions skipped: {0}", stats.RegionsSkippedUnreadable);
        Console.WriteLine("Open failures: {0}", stats.OpenFailures);
        Console.WriteLine("Read failures: {0}", stats.ReadFailures);
        Console.WriteLine("Query failures: {0}", stats.QueryFailures);
        Console.WriteLine("Bytes read: {0}", stats.BytesRead);

        Console.WriteLine();
        if (stats.Findings > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Risk: FOUND - Edge memory contained saved-password-like values. Passwords were masked in output.");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Risk: NOT FOUND - No saved-password-like values were detected in the audited scope.");
            Console.ResetColor();
        }
    }

    static void Main()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        bool isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
        string currentUser = identity.Name;
        int currentSessionId = Process.GetCurrentProcess().SessionId;
        string sessionName = SafeSessionName();

        Console.WriteLine("Edge saved-password exposure audit");
        Console.WriteLine("-----------------------------------");
        Console.WriteLine("Current user: {0}", currentUser);
        Console.WriteLine("Current session: {0} ({1})", currentSessionId, sessionName);
        Console.WriteLine("Running elevated: {0}", isElevated ? "yes" : "no");
        Console.WriteLine("Admin requirement: not required for the restricted current-user/current-session audit scope.");
        Console.WriteLine("Password output: masked only");
        Console.WriteLine();

        if (!ConfirmAudit())
        {
            Console.WriteLine("\nAudit cancelled.");
            return;
        }

        AuditStats stats = new AuditStats();
        HashSet<string> seenHashes = new HashSet<string>();

        List<ProcessInfo> processList;
        try
        {
            Console.WriteLine("\nFetching root Edge processes...");
            processList = GetRootEdgeProcesses();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to query Edge processes: " + ex.Message);
            return;
        }

        stats.DiscoveredRootProcesses = processList.Count;
        Console.WriteLine("Done. Found {0} root process candidate(s).\n", processList.Count);

        foreach (ProcessInfo proc in processList)
        {
            if (!IsCurrentUser(proc.Owner, currentUser))
            {
                stats.SkippedDifferentUser++;
                continue;
            }

            if (proc.SessionId != currentSessionId)
            {
                stats.SkippedDifferentSession++;
                continue;
            }

            Console.WriteLine("Auditing PID {0} | owner={1} | session={2} | Edge={3}",
                proc.Id,
                proc.Owner,
                proc.SessionId,
                proc.EdgeVersion);

            try
            {
                ScanProcess(proc, seenHashes, stats);
            }
            catch (Exception ex)
            {
                stats.ReadFailures++;
                Console.WriteLine("  Audit error: " + ex.Message);
            }
        }

        seenHashes.Clear();
        PrintSummary(stats);
    }
}
