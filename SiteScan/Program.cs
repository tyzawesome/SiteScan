using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net.Http;
using System.Threading.Tasks;

namespace SiteScanner
{
    class Program
    {
        // Commonly open / exploitable ports
        private static readonly int[] CommonPorts = { 20, 21, 22, 23, 80, 443, 3306, 139, 445, 53 };

        // A few paths to check for exposure
        private static readonly string[] CommonPaths =
        {
            "/robots.txt",
            "/.env",
            "/.git/",
            "/admin",
            "/phpinfo.php",
            "/test",
            "/dev"
        };

        // A list of security headers to check
        private static readonly string[] SecurityHeaders =
        {
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-XSS-Protection",
            "X-Content-Type-Options"
        };

        static async Task Main(string[] args)
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine(@"/***
 *      .-')             .-') _     ('-.          .-')                ('-.         .-') _      .-') _   ('-.  _  .-')  
 *     ( OO ).          (  OO) )  _(  OO)        ( OO ).             ( OO ).-.    ( OO ) )    ( OO ) )_(  OO)( \( -O ) 
 *    (_)---\_)  ,-.-') /     '._(,------.      (_)---\_)   .-----.  / . --. /,--./ ,--,' ,--./ ,--,'(,------.,------. 
 *    /    _ |   |  |OO)|'--...__)|  .---'      /    _ |   '  .--./  | \-.  \ |   \ |  |\ |   \ |  |\ |  .---'|   /`. '
 *    \  :` `.   |  |  \'--.  .--'|  |          \  :` `.   |  |('-..-'-'  |  ||    \|  | )|    \|  | )|  |    |  /  | |
 *     '..`''.)  |  |(_/   |  |  (|  '--.        '..`''.) /_) |OO  )\| |_.'  ||  .     |/ |  .     |/(|  '--. |  |_.' |
 *    .-._)   \ ,|  |_.'   |  |   |  .--'       .-._)   \ ||  |`-'|  |  .-.  ||  |\    |  |  |\    |  |  .--' |  .  '.'
 *    \       /(_|  |      |  |   |  `---.      \       /(_'  '--'\  |  | |  ||  | \   |  |  | \   |  |  `---.|  |\  \ 
 *     `-----'   `--'      `--'   `------'       `-----'    `-----'  `--' `--'`--'  `--'  `--'  `--'  `------'`--' '--'
 */");

                await Scan();

                Console.Write("\nWould you like to scan another host? (y/n) ");
                string answer = Console.ReadLine()?.Trim().ToLower() ?? "n";
                if (answer != "y")
                {
                    break;
                }
            }
        }

        private static async Task Scan()
        {
            Console.Write("\nEnter the target host (e.g., example.com): ");
            string targetHost = Console.ReadLine() ?? "localhost";

            // 1. Check Open Ports
            Console.WriteLine($"\n[+] Scanning {targetHost} for open ports...");
            var openPorts = CheckOpenPorts(targetHost, CommonPorts);
            if (openPorts.Count > 0)
            {
                Console.WriteLine("Open ports found: " + string.Join(", ", openPorts));
            }
            else
            {
                Console.WriteLine("No common ports open.");
            }

            // 2. Check Exposed Paths
            Console.WriteLine($"\n[+] Checking {targetHost} for exposed paths...");
            var exposedPaths = await CheckExposedPaths(targetHost, CommonPaths);
            if (exposedPaths.Count > 0)
            {
                Console.WriteLine("Exposed paths found: " + string.Join(", ", exposedPaths));
            }
            else
            {
                Console.WriteLine("No exposed paths found.");
            }

            // 3. Check for Missing Security Headers
            Console.WriteLine($"\n[+] Checking {targetHost} for missing security headers...");
            var missingHeaders = await CheckSecurityHeaders(targetHost, SecurityHeaders);
            if (missingHeaders.Count > 0)
            {
                Console.WriteLine("Missing or misconfigured headers: " + string.Join(", ", missingHeaders));
            }
            else
            {
                Console.WriteLine("No critical security headers are missing.");
            }
        }

        private static List<int> CheckOpenPorts(string host, int[] ports)
        {
            var openPorts = new List<int>();

            foreach (var port in ports)
            {
                using var client = new TcpClient();
                try
                {
                    // Try to connect within a short timeout
                    var result = client.BeginConnect(host, port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(500));

                    if (success && client.Connected)
                    {
                        openPorts.Add(port);
                    }
                }
                catch
                {
                    // Ignore exceptions -> means we couldn't connect
                }
            }

            return openPorts;
        }

        private static async Task<List<string>> CheckExposedPaths(string host, string[] paths)
        {
            var exposed = new List<string>();

            using HttpClient httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(2)
            };

            foreach (var path in paths)
            {
                try
                {
                    string url = $"http://{host}{path}";
                    var response = await httpClient.GetAsync(url);

                    if (response.IsSuccessStatusCode)
                    {
                        exposed.Add(path);
                    }
                }
                catch
                {
                    // Connection errors, timeouts, etc.
                }
            }

            return exposed;
        }

        private static async Task<List<string>> CheckSecurityHeaders(string host, string[] headersToCheck)
        {
            var missingHeaders = new List<string>();

            using HttpClient httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(3)
            };

            try
            {
                string url = $"http://{host}/";
                var response = await httpClient.GetAsync(url);

                // Check each header
                foreach (var header in headersToCheck)
                {
                    if (!response.Headers.Contains(header))
                    {
                        missingHeaders.Add(header);
                    }
                }
            }
            catch
            {
                // Can't connect at all -> no headers
            }

            return missingHeaders;
        }
    }
}
