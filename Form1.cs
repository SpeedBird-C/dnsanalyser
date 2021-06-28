using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.RegularExpressions;
using System.Numerics;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Core.Extensions;
using PcapDotNet.Packets;

namespace AnalyzerDNS
{
    public partial class Form1 : Form
    {
        SortedDictionary<string, SortedDictionary<string, SortedDictionary<string, Dictionary<ushort, MyQueryResponseInfo>>>> hostDictionary;

        SortedSet<string> addressIP;

        SortedSet<string> addressDNS;

        SortedSet<string> addressInsecure;

        SortedSet<string> addressSecure;

        public Form1()
        {
            InitializeComponent();
        }

        private class MyQueryResponseInfo
        {
            public double? queryTime;

            public double? responseTime;
        }

        private class MyImpostorInfo
        {
            public SortedDictionary<string, MySuspectNameInfo> suspectNameDictionary;

            public SortedDictionary<string, MySuspectNameInfo> frequentSuspectNameDictionary;

            public SortedDictionary<string, MySuspectNameInfo> mostSuspectNameDictionary;
        }

        private class MySuspectNameInfo
        {
            public long questionCount;

            public List<double> intervalResponseQuestion;

            public double truncatedMean;

            public double correctedSampleStandardDeviation;

            public double percentageScatter;
        }

        private void buttonBrowse_Click(object sender, EventArgs e)
        {
            //textBoxIP.Text = "";

            //textBoxDNS.Text = "";

            textBoxInsecure.Text = "";

            //textBoxSecure.Text = "";

            //textBoxAddrRegex.Text = "";

            textBoxSuspects.Text = "";

            //buttonIP.Enabled = false;

            //buttonDNS.Enabled = false;

            //buttonInsecure.Enabled = false;

            //buttonSecure.Enabled = false;

            //textBoxAddrRegex.Enabled = false;

            buttonAnalyze.Enabled = false;

            if (pcapFileDialog.ShowDialog() == DialogResult.OK)
            {
                var filePath = pcapFileDialog.FileName;

                var selectedDevice = new OfflinePacketDevice(filePath);

                try
                {
                    PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);

                    var filter = "ip proto 17 && (src port 53 || dst port 53)";

                    communicator.SetFilter(filter);

                    List<Packet> capturedPacket = communicator.ReceivePackets().ToList();

                    hostDictionary = new SortedDictionary<string, SortedDictionary<string, SortedDictionary<string, Dictionary<ushort, MyQueryResponseInfo>>>>();

                    addressIP = new SortedSet<string>();

                    addressDNS = new SortedSet<string>();

                    addressInsecure = new SortedSet<string>();

                    addressSecure = new SortedSet<string>();

                    foreach (Packet packet in capturedPacket)
                    {
                        var dataIP = packet.Ethernet.IpV4;

                        var dataDNS = dataIP.Udp.Dns;

                        if (0 != dataDNS.QueryCount && (dataDNS.IsQuery || dataDNS.IsResponse))
                        {
                            string sourceIP = "";

                            string destinationIP = "";

                            if (dataDNS.IsQuery)
                            {
                                sourceIP = dataIP.Source.ToString();

                                destinationIP = dataIP.Destination.ToString();
                            }
                            else if (dataDNS.IsResponse)
                            {
                                destinationIP = dataIP.Source.ToString();

                                sourceIP = dataIP.Destination.ToString();
                            }

                            var transactionID = dataDNS.Id;

                            var fileTime = packet.Timestamp.ToFileTime();

                            SortedDictionary<string, SortedDictionary<string, Dictionary<ushort, MyQueryResponseInfo>>> domainNameDictionary;

                            if (!hostDictionary.ContainsKey(sourceIP))
                            {
                                domainNameDictionary = new SortedDictionary<string, SortedDictionary<string, Dictionary<ushort, MyQueryResponseInfo>>>();

                                hostDictionary.Add(sourceIP, domainNameDictionary);

                                addressIP.Add(sourceIP);
                            }

                            domainNameDictionary = hostDictionary[sourceIP];

                            foreach (var question in dataDNS.Queries)
                            {
                                var domainName = question.DomainName.ToString();

                                SortedDictionary<string, Dictionary<ushort, MyQueryResponseInfo>> serverQueryDictionary;

                                if (!domainNameDictionary.ContainsKey(domainName))
                                {
                                    serverQueryDictionary = new SortedDictionary<string, Dictionary<ushort, MyQueryResponseInfo>>();

                                    domainNameDictionary.Add(domainName, serverQueryDictionary);
                                }

                                serverQueryDictionary = domainNameDictionary[domainName];

                                Dictionary<ushort, MyQueryResponseInfo> identifierDictionary;

                                if (!serverQueryDictionary.ContainsKey(destinationIP))
                                {
                                    identifierDictionary = new Dictionary<ushort, MyQueryResponseInfo>();

                                    serverQueryDictionary.Add(destinationIP, identifierDictionary);

                                    addressDNS.Add(destinationIP);
                                }

                                identifierDictionary = serverQueryDictionary[destinationIP];

                                MyQueryResponseInfo queryResponseInfo;

                                if (!identifierDictionary.ContainsKey(transactionID))
                                {
                                    queryResponseInfo = new MyQueryResponseInfo();

                                    identifierDictionary.Add(transactionID, queryResponseInfo);
                                }

                                queryResponseInfo = identifierDictionary[transactionID];

                                if (dataDNS.IsQuery && !queryResponseInfo.queryTime.HasValue)
                                {
                                    queryResponseInfo.queryTime = Convert.ToDouble(fileTime);
                                }
                                else if (dataDNS.IsResponse && !queryResponseInfo.responseTime.HasValue)
                                {
                                    queryResponseInfo.responseTime = Convert.ToDouble(fileTime);
                                }
                            }
                        }
                    }

                    addressIP.ExceptWith(addressDNS);

                    foreach (string addr in addressIP)
                    {
                        //textBoxIP.Text += addr + "\r\n";
                        textBoxInsecure.Text+=addr+"\r\n";
                    }
                    addressIP.Clear();
                    foreach (string addr in addressDNS)
                    {
                        //textBoxDNS.Text += addr + "\r\n";

                        textBoxInsecure.Text += addr + "\r\n";

                    }
                    addressDNS.Clear();

                    textBoxFile.Text = filePath;

                   // buttonIP.Enabled = true;

                    //buttonDNS.Enabled = true;

                    //buttonInsecure.Enabled = true;

                    //buttonSecure.Enabled = true;

                    //textBoxAddrRegex.Enabled = true;

                    buttonAnalyze.Enabled = true;
                }
                catch
                {
                    textBoxFile.Text = "Error: invalid pcap";
                }
            }
            else
            {
                textBoxFile.Text = "Error: invalid pcap";
            }

        }

        /*private void buttonIP_Click(object sender, EventArgs e)
        {
            try
            {
                var wildСard = new Regex(textBoxAddrRegex.Text);

                var removedAddr = new List<string>();

                foreach (string addr in addressDNS)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressIP.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressDNS.Remove(addr);
                }

                removedAddr = new List<string>();

                foreach (string addr in addressInsecure)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressIP.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressInsecure.Remove(addr);
                }

                removedAddr = new List<string>();

                foreach (string addr in addressSecure)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressIP.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressSecure.Remove(addr);
                }

                //textBoxIP.Text = "";

                //textBoxDNS.Text = "";

                textBoxInsecure.Text = "";

                textBoxSecure.Text = "";

                /*foreach (string addr in addressIP)
                {
                    //textBoxIP.Text += addr + "\r\n";
                }*/

                /*foreach (string addr in addressDNS)
                {
                    textBoxDNS.Text += addr + "\r\n";
                }

                foreach (string addr in addressInsecure)
                {
                    textBoxInsecure.Text += addr + "\r\n";
                }

                foreach (string addr in addressSecure)
                {
                    textBoxSecure.Text += addr + "\r\n";
                }
            }
            catch
            {

            }

            textBoxAddrRegex.Text = "";
        }*/

        /*private void buttonDNS_Click(object sender, EventArgs e)
        {
            try
            {
                var wildСard = new Regex(textBoxAddrRegex.Text);

                var removedAddr = new List<string>();

                foreach (string addr in addressIP)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressDNS.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressIP.Remove(addr);
                }

                removedAddr = new List<string>();

                foreach (string addr in addressInsecure)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressDNS.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressInsecure.Remove(addr);
                }

                removedAddr = new List<string>();

                foreach (string addr in addressSecure)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressDNS.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressSecure.Remove(addr);
                }

                //textBoxIP.Text = "";

                //textBoxDNS.Text = "";

                textBoxInsecure.Text = "";

                textBoxSecure.Text = "";

                /*foreach (string addr in addressIP)
                {
                    //textBoxIP.Text += addr + "\r\n";
                }*/

                /*foreach (string addr in addressDNS)
                {
                    textBoxDNS.Text += addr + "\r\n";
                }

                foreach (string addr in addressInsecure)
                {
                    textBoxInsecure.Text += addr + "\r\n";
                }

                foreach (string addr in addressSecure)
                {
                    textBoxSecure.Text += addr + "\r\n";
                }
            }
            catch
            {

            }

            textBoxAddrRegex.Text = "";
        }*/

        /*private void buttonInsecure_Click(object sender, EventArgs e)
        {
            try
            {
                var wildСard = new Regex(textBoxAddrRegex.Text);

                var removedAddr = new List<string>();

                foreach (string addr in addressIP)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressInsecure.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressIP.Remove(addr);
                }

                removedAddr = new List<string>();

                foreach (string addr in addressSecure)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressInsecure.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressSecure.Remove(addr);
                }

                removedAddr = new List<string>();

                foreach (string addr in addressDNS)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressInsecure.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressDNS.Remove(addr);
                }

                //textBoxIP.Text = "";

                //textBoxDNS.Text = "";

                textBoxInsecure.Text = "";

                textBoxSecure.Text = "";

                /*foreach (string addr in addressIP)
                {
                    //textBoxIP.Text += addr + "\r\n";
                }*/

                /*foreach (string addr in addressDNS)
                {
                    textBoxDNS.Text += addr + "\r\n";
                }

                foreach (string addr in addressInsecure)
                {
                    textBoxInsecure.Text += addr + "\r\n";
                }

                foreach (string addr in addressSecure)
                {
                    textBoxSecure.Text += addr + "\r\n";
                }
            }
            catch
            {

            }

            textBoxAddrRegex.Text = "";
        }*/

        /*private void buttonSecure_Click(object sender, EventArgs e)
        {
            try
            {
                var wildСard = new Regex(textBoxAddrRegex.Text);

                var removedAddr = new List<string>();

                foreach (string addr in addressIP)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressSecure.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressIP.Remove(addr);
                }

                removedAddr = new List<string>();

                foreach (string addr in addressInsecure)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressSecure.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressInsecure.Remove(addr);
                }

                removedAddr = new List<string>();

                foreach (string addr in addressDNS)
                {
                    if (wildСard.Match(addr).Success)
                    {
                        addressSecure.Add(addr);

                        removedAddr.Add(addr);
                    }
                }

                foreach (string addr in removedAddr)
                {
                    addressDNS.Remove(addr);
                }

                //textBoxIP.Text = "";

                //textBoxDNS.Text = "";

                textBoxInsecure.Text = "";

                textBoxSecure.Text = "";

                /*foreach (string addr in addressIP)
                {
                    //textBoxIP.Text += addr + "\r\n";
                }*/

                /*foreach (string addr in addressDNS)
                {
                    textBoxDNS.Text += addr + "\r\n";
                }

                foreach (string addr in addressInsecure)
                {
                    textBoxInsecure.Text += addr + "\r\n";
                }

                foreach (string addr in addressSecure)
                {
                    textBoxSecure.Text += addr + "\r\n";
                }
            }
            catch
            {

            }

            textBoxAddrRegex.Text = "";
        }*/

        private void buttonAnalyze_Click(object sender, EventArgs e)
        {
            //buttonIP.Enabled = false;

            //buttonDNS.Enabled = false;

            //buttonInsecure.Enabled = false;

            //buttonSecure.Enabled = false;

            //textBoxAddrRegex.Enabled = false;

            buttonAnalyze.Enabled = false;

            foreach (var addr in addressIP)
            {
                if (hostDictionary.ContainsKey(addr))
                {
                    hostDictionary.Remove(addr);
                }
            }

            foreach (var addr in addressDNS)
            {
                if (hostDictionary.ContainsKey(addr))
                {
                    hostDictionary.Remove(addr);
                }
            }

            foreach (var hostEntry in hostDictionary)
            {
                var domainNameDictionary = hostEntry.Value;

                foreach (var domainNameEntry in domainNameDictionary)
                {
                    var serverQueryDictionary = domainNameEntry.Value;

                    foreach (var addr in addressIP)
                    {
                        if (hostDictionary[hostEntry.Key][domainNameEntry.Key].ContainsKey(addr))
                        {
                            hostDictionary.Remove(addr);
                        }
                    }
                }
            }

            var safeDomainName = new SortedSet<string>();
            
            foreach (var addr in addressSecure)
            {
                foreach (var domainNameEntry in hostDictionary[addr])
                {
                    safeDomainName.Add(domainNameEntry.Key);
                }
            }

            foreach (var addr in addressInsecure)
            {
                foreach (var name in safeDomainName)
                {
                    hostDictionary[addr].Remove(name);
                }
            }

            foreach (var addr in addressSecure)
            {
                hostDictionary.Remove(addr);
            }

            var impostorDictionary = new SortedDictionary<string, MyImpostorInfo>();

            foreach (var hostEntry in hostDictionary)
            {
                var domainNameDictionary = hostEntry.Value;

                var suspectNameDictionary = new SortedDictionary<string, MySuspectNameInfo>();

                var frequentSuspectNameDictionary = new SortedDictionary<string, MySuspectNameInfo>();

                var mostSuspectNameDictionary = new SortedDictionary<string, MySuspectNameInfo>();

                var minInterval = Double.MaxValue;

                int questionCount = 0;

                foreach (var domainNameEntry in domainNameDictionary)
                {
                    var serverQueryDictionary = domainNameEntry.Value;

                    var domainName = domainNameEntry.Key;

                    var questionTime = new List<double>();

                    var requestTime = new List<double>();

                    foreach (var serverQueryEntry in serverQueryDictionary)
                    {
                        foreach (var identifierTimeEntry in serverQueryEntry.Value)
                        {
                            var identifierTimeValue = identifierTimeEntry.Value;

                            var queryTime = identifierTimeValue.queryTime;

                            var responseTime = identifierTimeValue.responseTime;

                            if (queryTime.HasValue)
                            {
                                questionTime.Add(queryTime.Value);
                            }

                            if (responseTime.HasValue)
                            {
                                requestTime.Add(responseTime.Value);
                            }
                        }
                    }

                    if (0 < questionTime.Count)
                    {
                        if (1 < questionTime.Count)
                        {
                            questionTime.Sort();
                        }

                        requestTime.Sort();

                        var intervalResponseQuestion = new List<double>();

                        for (int i = 0; (0 < requestTime.Count) && (i < questionTime.Count); i++)
                        {
                            int k;

                            for (k = 0; (k < requestTime.Count) && (requestTime[k] <= questionTime[i]); k++) ;

                            if (0 != k)
                            {
                                k--;

                                var intervalRQ = questionTime[i] - requestTime[k];

                                intervalResponseQuestion.Add(intervalRQ);

                                requestTime.RemoveRange(0, (k + 1));
                            }
                        }

                        if (0 < intervalResponseQuestion.Count)
                        {
                            var truncatedCount = Convert.ToInt32(Math.Round(0.01 * intervalResponseQuestion.Count));

                            if (0 == truncatedCount)
                            {
                                truncatedCount++;
                            }

                            var truncatedList = intervalResponseQuestion.ToArray().ToList<double>();

                            for (int i = 0; 0 != truncatedList.Count && i < truncatedCount; i++)
                            {
                                var minValue = truncatedList.Min();

                                truncatedList.Remove(minValue);
                            }

                            for (int i = 0; 0 != truncatedList.Count && i < truncatedCount; i++)
                            {
                                var maxValue = truncatedList.Max();

                                truncatedList.Remove(maxValue);
                            }

                            if (25 < truncatedList.Count)
                            {
                                var truncatedMean = computeSampleMean(truncatedList);

                                var correctedSampleStandardDeviation = computeCorrectedSampleStandardDeviation(truncatedList, truncatedMean);

                                var percentageScatter = correctedSampleStandardDeviation / truncatedMean;

                                if (0.9 > percentageScatter)
                                {
                                    var suspectNameInfo = new MySuspectNameInfo();

                                    suspectNameInfo.questionCount = questionTime.Count;

                                    suspectNameInfo.intervalResponseQuestion = intervalResponseQuestion;

                                    suspectNameInfo.truncatedMean = truncatedMean;

                                    suspectNameInfo.correctedSampleStandardDeviation = correctedSampleStandardDeviation;

                                    suspectNameInfo.percentageScatter = percentageScatter;

                                    suspectNameDictionary.Add(domainNameEntry.Key, suspectNameInfo);

                                    if (truncatedMean <= minInterval)
                                    {
                                        if (truncatedMean < minInterval)
                                        {
                                            frequentSuspectNameDictionary.Clear();
                                        }

                                        frequentSuspectNameDictionary.Add(domainName, suspectNameInfo);
                                    }

                                    if (suspectNameInfo.questionCount >= questionCount)
                                    {
                                        if (suspectNameInfo.questionCount > questionCount)
                                        {
                                            mostSuspectNameDictionary.Clear();
                                        }

                                        mostSuspectNameDictionary.Add(domainName, suspectNameInfo);
                                    }
                                }
                            }
                        }
                    }
                }

                if (0 < suspectNameDictionary.Count)
                {
                    var impostorInfo = new MyImpostorInfo();

                    impostorInfo.suspectNameDictionary = suspectNameDictionary;

                    impostorInfo.frequentSuspectNameDictionary = frequentSuspectNameDictionary;

                    impostorInfo.mostSuspectNameDictionary = mostSuspectNameDictionary;

                    impostorDictionary.Add(hostEntry.Key, impostorInfo);
                }
            }

            foreach (var impostorEntry in impostorDictionary)
            {
                var impostorIP = impostorEntry.Key;

                var impostorValue = impostorEntry.Value;

                var suspectNameDictionary = impostorValue.suspectNameDictionary;

                var frequentSuspectNameDictionary = impostorValue.frequentSuspectNameDictionary;

                var mostSuspectNameDictionary = impostorValue.frequentSuspectNameDictionary;

                textBoxSuspects.Text += "Suspect IP: " + impostorIP + "\r\n\r\n";

                textBoxSuspects.Text += "Most frequent requests:\r\n";

                foreach (var suspectNameEntry in frequentSuspectNameDictionary)
                {
                    var suspectNameValue = suspectNameEntry.Value;

                    var suspectName = suspectNameEntry.Key;

                    var interval = Convert.ToInt32(Math.Round(suspectNameValue.truncatedMean / 10000));

                    var questionCount = suspectNameValue.questionCount;

                    textBoxSuspects.Text += "Domain name - " + suspectName + "; interval between response and question - " + interval + " ms; number of questions - " + questionCount + "\r\n";
                }

                textBoxSuspects.Text += "\r\nMost requests:\r\n";

                foreach (var suspectNameEntry in mostSuspectNameDictionary)
                {
                    var suspectNameValue = suspectNameEntry.Value;

                    var suspectName = suspectNameEntry.Key;

                    var interval = Convert.ToInt32(Math.Round(suspectNameValue.truncatedMean / 10000));

                    var questionCount = suspectNameValue.questionCount;

                    textBoxSuspects.Text += "Domain name - " + suspectName + "; interval between response and question - " + interval + " ms; number of questions - " + questionCount + "\r\n";
                }

                textBoxSuspects.Text += "\r\nAll suspect requests:\r\n";

                foreach (var suspectNameEntry in suspectNameDictionary)
                {
                    var suspectNameValue = suspectNameEntry.Value;

                    var suspectName = suspectNameEntry.Key;

                    var interval = Convert.ToInt32(Math.Round(suspectNameValue.truncatedMean / 10000));

                    var questionCount = suspectNameValue.questionCount;

                    textBoxSuspects.Text += "Domain name - " + suspectName + "; interval between response and question - " + interval + " ms; number of questions - " + questionCount + "\r\n";
                }

                textBoxSuspects.Text += "\r\n\r\n\r\n";
            }
        }

        private double computeSampleMean(List<double> sample)
        {
            var sum = sample.Sum();

            var sampleMean = (double)sum / sample.Count;

            return sampleMean;
        }

        private double computeCorrectedSampleStandardDeviation(List<double> sample, double sampleMean)
        {
            var doubleSample = new List<double>();

            foreach (var item in sample)
            {
                doubleSample.Add(item * item);
            }

            var doubleSampleMean = computeSampleMean(doubleSample);

            return Math.Sqrt((doubleSample.Count * (doubleSampleMean - (sampleMean * sampleMean))) / (doubleSample.Count - 1));
        }
    }
}