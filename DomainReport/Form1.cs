using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.Drawing;
using System.Net.Http;
using System.Text;
using System.Windows.Forms;
using System.Xml.Linq;

namespace DomainInspectorGUI
{
    public partial class Form1 : Form
    {
        string lastJson = "";

        public Form1()
        {
            InitializeComponent();
        }

        // Run CMD commands safely
        private string RunCmd(string cmd)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                return output.Trim();
            }
            catch
            {
                return "ERROR";
            }
        }

        // Main Analysis
        private async void analyzeButton_Click(object sender, EventArgs e)
        {
            string input = inputBox.Text.Trim();

            if (input == "")
            {
                MessageBox.Show("Please enter a domain or IP address.");
                return;
            }

            print("=== Domain/IP Investigation ===\n\n", Color.Cyan);

            // DNS Resolve
            string dnsA = RunCmd("nslookup " + input + " | find \"Address:\"");
            print("IP Address:\n", Color.Yellow);
            print(dnsA + "\n\n", Color.White);

            // Reverse DNS
            string rdns = RunCmd("nslookup " + input + " | find \"name =\"");
            print("Reverse DNS:\n", Color.Yellow);
            print(rdns + "\n\n", Color.White);

            // NS Records
            string ns = RunCmd("nslookup -type=NS " + input);
            print("Nameservers:\n", Color.Yellow);
            print(ns + "\n\n", Color.White);

            // MX Records
            string mx = RunCmd("nslookup -type=MX " + input);
            print("Mail Servers:\n", Color.Yellow);
            print(mx + "\n\n", Color.White);

            // WHOIS (API)
            print("WHOIS Lookup:\n", Color.Yellow);
            string whois = await GetHttp($"https://api.hackertarget.com/whois/?q={input}");
            print(whois + "\n\n", Color.White);

            // GEO (API)
            print("Geolocation:\n", Color.Yellow);
            string geo = await GetHttp($"https://ipinfo.io/{input}/json");
            print(geo + "\n\n", Color.White);

            // Save JSON in memory
            JObject json = new JObject
            {
                ["input"] = input,
                ["a_record"] = dnsA,
                ["reverse_dns"] = rdns,
                ["nameservers"] = ns,
                ["mailservers"] = mx,
                ["whois"] = whois,
                ["geolocation"] = JObject.Parse(geo)
            };
            lastJson = json.ToString();

            print("Analysis complete.\n", Color.Green);
        }

        // HTTP Get
        private async System.Threading.Tasks.Task<string> GetHttp(string url)
        {
            try
            {
                HttpClient client = new HttpClient();
                return await client.GetStringAsync(url);
            }
            catch
            {
                return "ERROR";
            }
        }

        // Colored output
        private void print(string text, Color c)
        {
            resultBox.SelectionColor = c;
            resultBox.AppendText(text);
            resultBox.SelectionColor = Color.White;
        }

        private void exportButton_Click(object sender, EventArgs e)
        {
            if (lastJson == "")
            {
                MessageBox.Show("Run analysis first.");
                return;
            }

            SaveFileDialog sfd = new SaveFileDialog();
            sfd.Filter = "JSON file|*.json";
            sfd.FileName = "report.json";

            if (sfd.ShowDialog() == DialogResult.OK)
            {
                System.IO.File.WriteAllText(sfd.FileName, lastJson);
                MessageBox.Show("JSON saved.");
            }
        }
    }
}
