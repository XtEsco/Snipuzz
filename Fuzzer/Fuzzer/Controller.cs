using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Fuzzer
{
    class Controller
    {
        public static string last_cookie;
        public static string token;
        public static string responseStr;
        public static int sendCount = 0;
        public static Boolean sendErrorFlag = false;
        private int currentMessageIndex;

        public int CurrentMessageIndex { get => currentMessageIndex; set => currentMessageIndex = value; }

        public static List<Dictionary<string, string>> ReadInputFromFile(string file,string mode="record")
        {
            List<Dictionary<string, string>> inputList = new List<Dictionary<string, string>>();
            Dictionary<string, string> input = new Dictionary<string, string>();

            if (File.Exists(file))
            {
                StreamReader sr = new StreamReader(file, Encoding.UTF8);
                string line;
                string header;
                string content;

                    while ((line = sr.ReadLine()) != null)
                    {
                        if (line.Contains("===="))
                        {
                            if (input.Count != 0)
                            {
                                inputList.Add(input);
                            }
                            input = new Dictionary<string, string>();
                        }

                        if (line.Contains(":"))
                        {
                            header = line.Substring(0, line.IndexOf(':')).Trim();
                            content = line.Substring(line.IndexOf(':') + 1, line.Length - line.IndexOf(':') - 1).Trim();

                            if (Program.InputBytesMode == "Byte" && header=="Content" && mode == "record")
                            {
                                int NumberChars = content.Length;
                                byte[] bytes = new byte[NumberChars / 2];
                                //Console.WriteLine(content);
                                for (int i = 0; i< bytes.Length; i++)
                                {
                                    string temp = content.Substring(i * 2, 2);
                                    Console.WriteLine(temp);
                                    bytes[i] = Convert.ToByte(temp, 16);
                                }
                                content = Encoding.Unicode.GetString(bytes);
                            }
                            input.Add(header, content);
                            Console.WriteLine(header + " --- " + content);
                        }
                    }
                    inputList.Add(input);
                    sr.Close();
                }
            return inputList;
        }

        private void WriteInputs(List<Dictionary<string, string>> inputs)
        {
            FileStream fs = new FileStream(Program.OutFold + DateTime.Now.ToString("hh-mm-ss") + ".txt", FileMode.Create, FileAccess.Write);
            StreamWriter sw = new StreamWriter(fs);
            int index = 1;
            foreach (Dictionary<string, string> input in inputs)
            {
                sw.WriteLine(String.Format("====================  {0} ==========================", index));
                foreach (string key in input.Keys)
                {
                    sw.WriteLine(String.Format("{0}  : {1}", key, input[key]));
                }
                sw.WriteLine();
            }
            sw.Close();
            fs.Close();

        }

        public List<string> SendInputList(List<Dictionary<string, string>> inputs)
        {
            if (sendErrorFlag) sendCount++;
            else sendCount = 0;

            List<string> resList = new List<string>();
            last_cookie = "";
            token = "";

            Program.TstartTime = new List<string>();
            Program.TendTime = new List<string>();

            System.Diagnostics.Process p = new System.Diagnostics.Process();

            currentMessageIndex = 0;

            /* use tshark to monitor connections */
            if (Fuzzer.Program.fuzzMode == 1)
            {
                p.StartInfo.FileName = Program.TsharkPath;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardInput = true;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.CreateNoWindow = true;

                Program.testStrat(p);
                Thread.Sleep(500);
            }

            foreach (Dictionary<string, string> input in inputs)
            {

                responseStr = "";

                CancellationTokenSource cts = new CancellationTokenSource();
                CancellationToken CTStoken = cts.Token;

                /*************** Send message and get responses from server *****************/
                Task t = new Task(() =>
                {
                    Program.TstartTime.Add(DateTime.Now.TimeOfDay.ToString());
                    HttpWebRequest request;

                    if (input.ContainsKey("URL"))
                    {
                        //Console.WriteLine(input["URL"]);
                        request = (HttpWebRequest)WebRequest.Create(input["URL"]);
                        //request.Timeout = 5 * 1000;
                        foreach (string key in input.Keys)
                        {
                            switch (key)
                            {
                                case "ContentType":
                                    request.ContentType = input[key];
                                    break;
                                case "Method":
                                    request.Method = input[key];
                                    break;
                                case "URL":
                                    break;
                                case "Content":
                                    break;
                                default:
                                    request.Headers.Add(key, input[key]);
                                    break;
                            }
                        }
                        if (!last_cookie.Equals("")) request.Headers.Add("Cookie", last_cookie);

                        /* send the message to server */
                        Stream reqStream = request.GetRequestStream();
                        reqStream.Write(Encoding.Default.GetBytes(input["Content"]), 0, input["Content"].Length);
                        try
                        {
                            // get the response from server
                            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                            Stream resStream = response.GetResponseStream();

                            string cookie = response.GetResponseHeader("set-cookie");
                            if (!cookie.Equals("")) last_cookie = cookie;

                            StreamReader readStream = new StreamReader(resStream, Encoding.GetEncoding("utf-8"));
                            string res = readStream.ReadToEnd().Trim();

                            response.Close();
                            resStream.Close();
                            reqStream.Close();
                            readStream.Close();
                            //Console.WriteLine("cookie ==== " + cookie);
                            //Console.WriteLine(res);

                            responseStr = res;

                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("e:" + e.Message);
                        }
                    }
                    else
                    {
                        responseStr = "No URL found in input";
                    }

                });

                if (Program.ConnectMode.Equals("Socket"))
                {
                    //Console.WriteLine("++++++++");

                    t = new Task(() =>
                    {
                        Program.TstartTime.Add(DateTime.Now.TimeOfDay.ToString());

                        Socket socket = null;
                        socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        socket.SendTimeout = 500;
                        try
                        {
                            IPAddress address = IPAddress.Parse(Program.DeviceIP);
                            IPEndPoint endPoint = new IPEndPoint(address, Convert.ToInt32(input["Port"]));
                            socket.Connect(endPoint);

                            //Console.WriteLine("------------");
                            //Console.WriteLine(tempContent);
                            if (Program.InputBytesMode == "Byte")
                            {
                                //Console.WriteLine(input["Content"]);
                                socket.Send(Encoding.Unicode.GetBytes(input["Content"]));
                            }
                            else
                            {
                                //Console.WriteLine(input["Content"]);
                                string tempContent = input["Content"] + "\r\n";
                                if (input.ContainsKey("Header"))
                                {
                                    input["Header"] = input["Header"].Replace("|", "\r\n");
                                    tempContent = input["Header"] + "Content-Length: " + input["Content"].Length + "\r\n\r\n" + input["Content"];
                                }
                                socket.Send(Encoding.UTF8.GetBytes(tempContent));
                            }
                            

                            Byte[] RecvBytes = new Byte[1024 * 4];
                            int iBytes = 1;

                            iBytes = socket.Receive(RecvBytes, RecvBytes.Length, 0);
                            if(Program.InputBytesMode == "Byte")
                            {
                                for (int i = 0; i < RecvBytes.Length; i++)
                                {
                                    responseStr += RecvBytes[i].ToString("x2") + " ";
                                }
                                //Console.WriteLine(responseStr);
                            }
                            else
                            {
                                responseStr = Encoding.UTF8.GetString(RecvBytes, 0, iBytes);
                            }
                            
                            //Console.WriteLine(responseStr);
                            
                            socket.Close();
                        }
                        catch (Exception ex)
                        {
                            socket.Close();
                            Console.WriteLine("Error 1:"+ ex.Message);
                        }

                    });
                }

                /****** Set up timeout for the task *****/
                Task timeout = new Task(() =>
                {
                    System.Threading.Thread.Sleep(TimeSpan.FromSeconds(5));
                }, CTStoken);

                //Console.WriteLine("Task Starts");
                t.Start();
                timeout.Start();

                System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
                sw.Start();

                while (!timeout.IsCompleted)
                {
                    if (t.IsCompleted)
                    {
                        cts.Cancel();
                        break;
                    }
                }

                //Console.WriteLine("Task Ends");
                sw.Stop();

                //Console.WriteLine("Time elapsed: {0}", sw.Elapsed);

                if (responseStr == "")
                {

                    Console.WriteLine("*Resend = " + sendCount + "*");

                    if (sendCount > 6)
                    {
                        WriteInputs(inputs);
                        Console.WriteLine("Error : Maybe we have triged a crash or maybe it`s something wrong with net traffic");
                        return null;
                        //System.Environment.Exit(0);
                    }

                    if (sendCount > 5)
                    {
                        Console.WriteLine("Physically resotring .......");
                        WriteInputs(inputs);
                        // Physically restore the device
                        foreach (Dictionary<string, string> n in Program.PhyRestoreInput)
                        {
                            string restoreRes = RequestAndResponse(n);
                            if (restoreRes.Contains("token"))
                            {
                                token = restoreRes.Substring(responseStr.IndexOf("token") + 8, responseStr.LastIndexOf("\"") - responseStr.IndexOf("token") - 8);
                                for (int i = 1; i < Program.PhyRestoreInput.Count; i++)
                                {
                                    if (Program.PhyRestoreInput[i]["URL"].Contains("token"))
                                    {
                                        string url = Program.PhyRestoreInput[i]["URL"];
                                        url = url.Remove(url.IndexOf("token") + 6, url.IndexOf("&") - url.IndexOf("token") - 6).Insert(url.IndexOf("token") + 6, token);
                                        //Console.WriteLine(url);
                                        Program.PhyRestoreInput[i]["URL"] = url;
                                    }
                                }
                            }

                            Thread.Sleep(3000);
                        }

                        Thread.Sleep(60000);
                    }

                    sendErrorFlag = true;
                    //Thread.Sleep(2000);
                    resList = SendInputList(inputs);

                    sendErrorFlag = false;

                    return resList;
                }
                Program.TendTime.Add(DateTime.Now.TimeOfDay.ToString());
                //t.Dispose();

                /* replace the token */
                if (responseStr.Contains("token"))
                {
                    token = responseStr.Substring(responseStr.IndexOf("token") + 8, responseStr.LastIndexOf("\"") - responseStr.IndexOf("token") - 8);
                    //Console.WriteLine(token);

                    for (int i = 1; i < inputs.Count; i++)
                    {
                        if (inputs[i]["URL"].Contains("token"))
                        {
                            string url = inputs[i]["URL"];
                            url = url.Remove(url.IndexOf("token") + 6, url.IndexOf("&") - url.IndexOf("token") - 6).Insert(url.IndexOf("token") + 6, token);
                            //Console.WriteLine(url);
                            inputs[i]["URL"] = url;
                        }
                    }
                }
                if (Program.fuzzMode == 1)
                {
                    if (Program.currentStep.Equals("Detection4Randonmness") || Program.currentStep.Equals("FirstState")) Thread.Sleep(1000);
                }

                //Thread.Sleep(1000);

                currentMessageIndex++;
                resList.Add(responseStr);
                //Console.WriteLine();
            }

            /* use tshark to monitor connections */
            if (Fuzzer.Program.fuzzMode == 1)
            {
                Program.TstartTime.Add("23:59:59.999999999");
                Thread.Sleep(2000);
                Program.testEnd(p);
            }

            /* send restore message */
            if (Program.ConnectMode.Equals("Socket"))
            {
                Socket socket = null;
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.SendTimeout = 500;
                try
                {
                    Thread.Sleep(200);
                    foreach (Dictionary<string, string> input in Program.RestoreInput)
                    {
                        IPAddress address = IPAddress.Parse(Program.DeviceIP);
                        IPEndPoint endPoint = new IPEndPoint(address, Convert.ToInt32(input["Port"]));
                        socket.Connect(endPoint);

                        string tempContent = input["Content"];
                        if (input.ContainsKey("Header"))
                        {
                            input["Header"] = input["Header"].Replace("|", "\r\n");
                            tempContent = input["Header"] + "Content-Length: " + input["Content"].Length + "\r\n\r\n" + input["Content"];
                        }

                        socket.Send(Encoding.UTF8.GetBytes(tempContent + "\r\n"));

                        //Byte[] RecvBytes = new Byte[1024 * 4];
                        //int iBytes = 1;

                        //iBytes = socket.Receive(RecvBytes, RecvBytes.Length, 0);
                        //responseStr = Encoding.UTF8.GetString(RecvBytes, 0, iBytes);
                        //Console.WriteLine(responseStr);
                    }
                    socket.Close();

                }
                catch (Exception ex)
                {
                    socket.Close();
                    //Console.WriteLine("Error 2: "+ex.Message);
                    //foreach (char o in Encoding.UTF8.GetBytes(ex.Message)) Console.Write(o);
                }  
            }
            else
            {
                foreach (Dictionary<string, string> input in Program.RestoreInput)
                {
                    string restoreRes = RequestAndResponse(input);
                    if (restoreRes.Contains("token"))
                    {
                        token = restoreRes.Substring(responseStr.IndexOf("token") + 8, responseStr.LastIndexOf("\"") - responseStr.IndexOf("token") - 8);
                        for (int i = 1; i < Program.RestoreInput.Count; i++)
                        {
                            if (Program.RestoreInput[i]["URL"].Contains("token"))
                            {
                                string url = Program.RestoreInput[i]["URL"];
                                url = url.Remove(url.IndexOf("token") + 6, url.IndexOf("&") - url.IndexOf("token") - 6).Insert(url.IndexOf("token") + 6, token);
                                //Console.WriteLine(url);
                                Program.RestoreInput[i]["URL"] = url;
                            }
                        }
                    }
                }
            }
            

            if (resList.Count == 0)
            {
                

                resList = SendInputList(inputs);
            }
            else
            {
                sendErrorFlag = false;
            }

            return resList;
        }


        /* Backup Method  */
        public string RequestAndResponse(Dictionary<string, string> input)
        {
            HttpWebRequest request;
            //Console.WriteLine("in Task");

            if (input.ContainsKey("URL"))
            {
                //Console.WriteLine(input["URL"]);
                request = (HttpWebRequest)WebRequest.Create(input["URL"]);
                request.Timeout = 5 * 1000;
                foreach (string key in input.Keys)
                {
                    switch (key)
                    {
                        case "ContentType":
                            request.ContentType = input[key];
                            break;
                        case "Method":
                            request.Method = input[key];
                            break;
                        case "URL":
                            break;
                        case "Content":
                            break;
                        default:
                            request.Headers.Add(key, input[key]);
                            break;
                    }
                }
                if (!last_cookie.Equals("")) request.Headers.Add("Cookie", last_cookie);

                
                try
                {
                    Stream reqStream = request.GetRequestStream();
                    reqStream.Write(Encoding.Default.GetBytes(input["Content"]), 0, input["Content"].Length);
                    // get the response from server
                    HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                    Stream resStream = response.GetResponseStream();

                    string cookie = response.GetResponseHeader("set-cookie");
                    if (!cookie.Equals("")) last_cookie = cookie;

                    StreamReader readStream = new StreamReader(resStream, Encoding.GetEncoding("utf-8"));
                    string res = readStream.ReadToEnd().Trim();

                    response.Close();
                    resStream.Close();
                    reqStream.Close();
                    readStream.Close();
                    //Console.WriteLine("cookie ==== " + cookie);
                    //Console.WriteLine(res);

                    responseStr = res;

                    return res;
                }
                catch (Exception e)
                {
                    Console.WriteLine("e:" + e.Message);

                }
            }
            responseStr = "No URL found in input";
            return "No URL found in input";
        }

    }
}
