using Aglomera;
using Aglomera.D3;
using Aglomera.Linkage;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using static Fuzzer.Cluster;

namespace Fuzzer
{
    class Program
    {
        /* Globy Settings */
        public static string DeviceName;

        public static int fuzzMode;
        public static Boolean recordMode;
        public static string ConnectMode;
        public static string InputBytesMode;

        public static string OriInputFile;
        public static string RestoreInputFile;
        public static string DictionaryFile;
        public static string RecordFile;
        public static string OutFold;
        public static string RecordFold;
        public static string PhysicalRestoreFile;
        public static string InterestingValueFile;

        public static string TsharkPath;
        public static string InterfaceName;
        public static string ServerIP;
        public static string DeviceIP;

        public static string MonitorMessage;
        public static List<int> MonitorMessageIndex;
        public static List<int> CurrentMonitorMessageIndex;
        public static List<string> TstartTime;
        public static List<string> TendTime;

        public static List<List<int>> firstState;
        public static List<List<int>> firstType;
        public static List<double> compareList;
        public static List<TreeNode> FamilyTree;

        public static List<List<string>> ResponseTypeLibrary;
        public static List<List<Double>> ResponseRandomnessList;

        public static string[] TestInt8 = { "-128", "-1", "0", "1", "16", "32", "64", "10", "127" };
        public static string[] TestInt16 = { "-32768", "-129", "128", "255", "256", "512", "1000", "1024", "4096", "32767" };
        public static string[] TestInt32 = { "-2147483648", "-100663046", "-32769", "32768", "65535", "65536", "100663045", "2147483647" };
        public static List<string[]> TestInt;
        public static List<string> InterestingValue;

        public static List<int[]> typeMap;
        public static List<List<string>> typeResponseList;

        public static Controller controller;

        public static SeedList LoopSeedList;
        public static SeedList RecordSeedList;
        public static Seed currentSeed;
        public static List<Dictionary<string, string>> curInput = new List<Dictionary<string, string>>();
        public static List<List<int>> curState = new List<List<int>>();
        public static List<int> StateHashList = new List<int>();

        public static List<Dictionary<string, string>> RestoreInput;
        public static List<Dictionary<string, string>> PhyRestoreInput;

        public static string currentStep;

        public class SeedList
        {
            public List<Seed> seeds;
            public SeedList(Seed s)
            {
                this.seeds = new List<Seed>();
                this.seeds.Add(s);
            }

            public Boolean isSeedListEmpty()
            {
                if (seeds.Count != 0) return false;
                return true;
            }

            public Seed pickNext(Seed currentSeed)
            {
                int index = seeds.IndexOf(currentSeed);
                seeds.Remove(currentSeed);
                if (this.isSeedListEmpty()) return null;
                else return seeds[index];
            }
        }

        public class Seed
        {
            public Seed(List<Dictionary<string, string>> Input, List<string> Responses, List<List<int>> States, List<List<int>> Types)
            {
                this.Input = Input;
                this.Responses = Responses;
                this.States = States;
                this.Types = Types;
            }
            public List<Dictionary<string, string>> Input { set; get; }
            public List<string> Responses { set; get; }
            public List<List<int>> States { set; get; }
            public List<List<int>> Types { set; get; }
        }

        public class TreeNode
        {
            public int index { set; get; }
            public string content { set; get; }
            public IList<TreeNode> children = new List<TreeNode>();
            public virtual void AddChildren(TreeNode node)
            {
                this.children.Add(node);
            }

            public virtual void RemoveChildren(TreeNode node)
            {
                this.children.Remove(node);
            }

            public virtual List<int> GetChildrenIndex()
            {
                if (this.children.Count == 0) return null;

                List<int> indexList = new List<int>();
                foreach (TreeNode child in children)
                {
                    indexList.Add(child.index);
                    List<int> childList = child.GetChildrenIndex();
                    if (childList != null)
                    {
                        foreach (int i in childList) indexList.Add(i);
                    }
                }

                return indexList;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        private static List<Dictionary<string, string>> ReadInputFromFile(string file)
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

                    if (line.Contains(':'))
                    {
                        header = line.Substring(0, line.IndexOf(':'));
                        content = line.Substring(line.IndexOf(':') + 1, line.Length - line.IndexOf(':') - 1);

                        input.Add(header, content);
                        //Console.WriteLine(header+" --- "+content);
                    }
                }
                inputList.Add(input);
                sr.Close();
            }
            return inputList;
        }


        /* debug method */
        // call the cmd.exe and execute tshark to monitor communication between IoT devices and AP（router）
        public static string ExecuteCMD()
        {
            //string str = TsharkPath + " -i "+ InterfaceName +" -l";
            string str = TsharkPath + " -i " + InterfaceName + " -Y \"ip.src == " + DeviceIP + " \" -l -aduration:5";
            //string str = TsharkPath + " -s 0 -l -c 10";
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();

            /* wait for signal */

            p.StandardInput.WriteLine(str + "&exit");
            p.StandardInput.AutoFlush = true;
            string output = p.StandardOutput.ReadToEnd();

            p.WaitForExit();
            p.Close();
            return output;
        }


        private static void DryRun(List<Dictionary<string, string>> input)
        {
            currentStep = "DryRun";

            List<List<int>> state = new List<List<int>>();
            List<List<int>> type = new List<List<int>>();
            Console.WriteLine("====================== Response Library Initialization ======================");
            ResponseLibraryInitialization(input, ref state, ref type);
            firstState = state;
            firstType = type;


            foreach (Dictionary<string, string> o in input) Console.WriteLine(o["Content"]);


            /* Record the dry run result in txt file */
            string tFile = RecordFold + DateTime.Now.ToString("hh-mm-ss") + ".txt";
            try
            {
                FileStream oFileStream = new FileStream(tFile, FileMode.Create, FileAccess.Write);
                StreamWriter sw = new StreamWriter(oFileStream);

                /* First State Result */
                sw.WriteLine("First Status - Begin");
                for (int index = 0; index < input.Count; index++)
                {
                    sw.WriteLine("=====================================================");
                    sw.WriteLine("Message " + (index + 1) + " :\n");
                    sw.WriteLine(input[index]["Content"]);
                    if (fuzzMode == 1)
                    {
                        for (int i = 0; i < firstState[index].Count; i++)
                        {
                            sw.Write(firstState[index][i] + " ");
                        }
                        sw.WriteLine();
                    }

                    for (int i = 0; i < firstType[index].Count; i++)
                    {
                        sw.Write(firstType[index][i] + " ");
                    }
                    sw.WriteLine("\n");
                }
                sw.WriteLine("\nFirst Status - End\n");

                /* Response Type Result */
                sw.WriteLine("Response Type - Begin");
                for (int i = 0; i < ResponseTypeLibrary.Count; i++)
                {
                    sw.WriteLine("Index - " + i);
                    for (int j = 0; j < ResponseTypeLibrary[i].Count; j++)
                    {
                        sw.WriteLine("===============");
                        sw.WriteLine(ResponseTypeLibrary[i][j]);
                        sw.WriteLine("---------------");
                        sw.WriteLine(ResponseRandomnessList[i][j]);
                        sw.WriteLine("+++++++++++++++");
                    }
                    sw.WriteLine("Index - End");
                    sw.WriteLine('\n');

                }
                sw.WriteLine("\nResponse Type - End\n");

                sw.Close();
                oFileStream.Close();


            }
            catch (Exception eX)
            {
                Console.WriteLine("Write Seesion List Error : " + eX.Message);
            }



        }

        private static List<double> Detection4Randonmness(List<Dictionary<string, string>> input)
        {

            currentStep = "Detection4Randonmness";
            List<double> compare = new List<double>();

            List<string> firstRes = controller.SendInputList(input);
            //Console.WriteLine("\nCurrentMonitorMessageIndex = "+CurrentMonitorMessageIndex.Count);
            //foreach(int i in CurrentMonitorMessageIndex) Console.Write(" " + i);
            //Console.WriteLine();

            Thread.Sleep(3000);

            List<string> secondRes = controller.SendInputList(input);
            //Console.WriteLine("\nCurrentMonitorMessageIndex = " + CurrentMonitorMessageIndex.Count);
            //foreach (int i in CurrentMonitorMessageIndex) Console.Write(" " + i);
            //Console.WriteLine();

            for (int i = 0; i < firstRes.Count; i++)
            {
                Console.WriteLine("No " + i);
                Console.WriteLine("V1 :");
                Console.WriteLine(firstRes[i]);
                Console.WriteLine("V2 :");
                Console.WriteLine(secondRes[i]);
                compare.Add(AnaylseComparation(firstRes[i], secondRes[i]));
                Console.WriteLine("Result :" + compare[i] + "\n");
            }
            return compare;
        }

        private static double AnaylseComparation(string v1, string v2)
        {
            double similarity = CompareStrings(v1, v2);
            return similarity;
        }

        private static void FirstStateAndType(List<Dictionary<string, string>> inputs)
        {
            currentStep = "FirstState";
            List<List<int>> states = new List<List<int>>();
            List<List<int>> types = new List<List<int>>();
            List<string> tResponseList = new List<string>();
            List<Dictionary<string, string>> tempInput = new List<Dictionary<string, string>>();
            ResponseTypeLibrary = new List<List<string>>();

            /* Record the original message response */
            List<string> ResponseList = controller.SendInputList(inputs);

            foreach (Dictionary<string, string> input in inputs) tempInput.Add(input);

            /* The first message should be login and we don`t need to detect */
            List<int> o = new List<int>();
            List<string> r = new List<string>();
            List<int> n = new List<int>();
            for (int i = 0; i < tempInput[0]["Content"].Length; i++)
            {
                n.Add(0);
                o.Add(0);
            }
            types.Add(n);
            if (fuzzMode == 1) states.Add(o);
            r.Add(ResponseList[0]);
            ResponseTypeLibrary.Add(r);


            for (int i = 1; i < inputs.Count; i++)
            {
                string tempString = tempInput[i]["Content"];
                List<int> state = new List<int>();
                List<int> type = new List<int>();
                List<string> resType = new List<string>();
                resType.Add(ResponseList[i]);

                Console.WriteLine(tempString);

                for (int index = 0; index < tempInput[i]["Content"].Length; index++)
                {
                    string str = tempInput[i]["Content"];
                    string tempstr = tempInput[i]["Content"];
                    str = str.Remove(index, 1);
                    //str = str.Insert(index, " ");
                    tempInput[i]["Content"] = str;
                    tResponseList = controller.SendInputList(tempInput);

                    /* Add state */
                    if (fuzzMode == 1)
                    {
                        state.Add(AnalyseState(i, tResponseList, ResponseList));
                        Console.Write(state[index]);
                    }

                    /* Add Response type to List if it`s new */
                    Boolean flag = false;
                    int typeIndex = -1;
                    foreach (string response in resType)
                    {
                        if (CompareResponses(i, response, tResponseList[i]))
                        {
                            typeIndex = resType.IndexOf(response);
                            flag = true;
                            break;
                        }
                    }
                    if (!flag)
                    {
                        resType.Add(tResponseList[i]);
                        typeIndex = resType.IndexOf(tResponseList[i]);
                    }

                    /* Add Response type to a numerical list */
                    type.Add(typeIndex);
                    Console.Write(type[index]);

                    tempInput[i]["Content"] = tempstr;
                    //Console.Write(state[index]);
                }

                Console.WriteLine();
                if (fuzzMode == 1) states.Add(state);
                types.Add(type);
                ResponseTypeLibrary.Add(resType);
            }

            firstState = new List<List<int>>();
            firstType = new List<List<int>>();

            if (fuzzMode == 1) firstState = states;
            firstType = types;
        }

        /* Not_Match        -> 0
         * Server_Reject    -> 1
         * Normal           -> 2
         * Impact           -> 3
         */
        private static int AnalyseState(int index, List<string> tResponseList, List<string> responseList)
        {
            /* if there is no connection between iot device and server */
            if (!CurrentMonitorMessageIndex.Contains(index)) return 1;


            if (CompareResponses(index, tResponseList[index], responseList[index]))
            {
                if (FamilyTree[index].children.Count != 0)
                {
                    foreach (TreeNode child in FamilyTree[index].children)
                    {
                        if (!CompareResponses(child.index, tResponseList[child.index], responseList[child.index]))
                        {
                            return 3;
                        }
                    }
                }
                else
                {
                    return 3;
                }
                return 2;
            }
            else
            {
                return 3;
            }

        }

        /* find the relationships fo each message and store them in a tree */
        private static List<TreeNode> FamilyTreeGenerate(List<Dictionary<string, string>> oriInput)
        {
            currentStep = "FamilyTreeGenerate";
            List<TreeNode> treeList = new List<TreeNode>();
            List<string> ResponseList = controller.SendInputList(oriInput);
            List<string> tResponseList = new List<string>();
            List<Dictionary<string, string>> treeInput = new List<Dictionary<string, string>>();
            foreach (Dictionary<string, string> input in oriInput) treeInput.Add(input);
            string tempContent;

            /* initialize the tree */
            int index = 0;
            foreach (Dictionary<string, string> input in oriInput)
            {
                TreeNode node = new TreeNode();
                node.index = index;
                node.content = input["Content"];
                index++;
                treeList.Add(node);
            }

            /* the first message (login) */
            for (int i = 1; i < oriInput.Count; i++)
            {
                treeList[0].AddChildren(treeList[i]);
            }

            Console.WriteLine(treeList[0].children.Count);

            /* generate the tree */
            for (int i = 1; i < oriInput.Count - 1; i++)
            {
                Console.WriteLine("i = " + i);
                tempContent = oriInput[i]["Content"];

                treeInput[i]["Content"] = " ";
                tResponseList = controller.SendInputList(treeInput);
                treeInput[i]["Content"] = tempContent;

                List<int> childrenIndex = FindChildrenByResponse(i, ResponseList, tResponseList);
                foreach (int child in childrenIndex)
                {
                    treeList[i].AddChildren(treeList[child]);
                }
            }
            Boolean firstflag = true;
            return treeList;
        }

        private static List<int> FindChildrenByResponse(int index, List<string> responseList, List<string> tResponseList)
        {
            Console.WriteLine("ResponseList :");
            foreach (string res in tResponseList) Console.WriteLine(res);

            List<int> childrenIndex = new List<int>();

            if (responseList.Count != tResponseList.Count) return null;
            for (int i = index + 1; i < responseList.Count; i++)
            {
                if (!CompareResponses(i, responseList[i], tResponseList[i]))
                {
                    childrenIndex.Add(i);
                }
            }
            return childrenIndex;
        }

        /* Compare two responses string
           True = Same or Similar Responses
           False = Different Responses
        */
        private static bool CompareResponses(double limit, string v1, string v2)
        {

            double similarity = CompareStrings(v1, v2);
            if (similarity >= limit) return true;

            return false;
        }

        public static double CompareStrings(string str1, string str2)
        {
            List<string> pairs1 = WordLetterPairs(str1.ToUpper());
            List<string> pairs2 = WordLetterPairs(str2.ToUpper());

            int intersection = 0;
            int union = pairs1.Count + pairs2.Count;

            for (int i = 0; i < pairs1.Count; i++)
            {
                for (int j = 0; j < pairs2.Count; j++)
                {
                    if (pairs1[i] == pairs2[j])
                    {
                        intersection++;
                        pairs2.RemoveAt(j);
                        break;
                    }
                }
            }
            return (2.0 * intersection) / union;
        }

        private static List<string> WordLetterPairs(string str)
        {
            List<string> AllPairs = new List<string>();
            string[] Words = Regex.Split(str, @"\s");

            for (int w = 0; w < Words.Length; w++)
            {
                if (!string.IsNullOrEmpty(Words[w]))
                {
                    String[] PairsInWord = LetterPairs(Words[w]);
                    for (int p = 0; p < PairsInWord.Length; p++)
                    {
                        AllPairs.Add(PairsInWord[p]);
                    }
                }
            }
            return AllPairs;
        }

        private static string[] LetterPairs(string str)
        {
            int numPairs = str.Length - 1;
            string[] pairs = new string[numPairs];
            for (int i = 0; i < numPairs; i++) pairs[i] = str.Substring(i, 2);
            return pairs;
        }


        /* Delete all the unesseary messages which are not sent to device */
        private static List<Dictionary<string, string>> Trim(List<Dictionary<string, string>> oriInput)
        {
            currentStep = "Trim";
            List<int> Cindex = new List<int>();
            List<Dictionary<string, string>> TrimInput = new List<Dictionary<string, string>>();
            List<string> responseList = controller.SendInputList(oriInput);
            foreach (string str in responseList)
            {
                Console.WriteLine(str);
            }


            foreach (Dictionary<string, string> o in oriInput) TrimInput.Add(o);

            Console.WriteLine("Message Index:");
            foreach (int o in MonitorMessageIndex)
            {
                Cindex.Add(o);
                Console.Write(o + " ");
            }
            Console.WriteLine();

            int i = 1;
            while (i < TrimInput.Count)
            {
                if (!Cindex.Contains(i))
                {
                    //Console.WriteLine("==============================================================")
                    //Console.WriteLine("Trim " + i);
                    //Console.WriteLine("Original Response");
                    //foreach (string o in responseList) Console.WriteLine(o);

                    Dictionary<string, string> tempDic = TrimInput[i];
                    TrimInput.Remove(TrimInput[i]);
                    for (int o = 0; o < Cindex.Count; o++) if (Cindex[o] > i) Cindex[o]--;

                    List<string> trimResponse = controller.SendInputList(TrimInput);
                    //Console.WriteLine("\nTrimed Response");
                    //foreach (string o in trimResponse) Console.WriteLine(o);

                    Boolean flag = true;
                    for (int j = 0; j < Cindex.Count; j++)
                    {
                        Console.WriteLine("==========================================");
                        Console.WriteLine(tempDic["Content"]);
                        Console.WriteLine("i=" + i + "    Cindex=" + Cindex[j]);
                        Console.WriteLine(responseList[MonitorMessageIndex[j]]);
                        Console.WriteLine(trimResponse[Cindex[j]]);
                        if (!CompareResponses(MonitorMessageIndex[j], responseList[MonitorMessageIndex[j]], trimResponse[Cindex[j]])) flag = false;
                    }

                    if (flag)
                    {
                        i--;
                    }
                    else
                    {
                        for (int o = 0; o < Cindex.Count; o++) if (Cindex[o] >= i) Cindex[o]++;
                        TrimInput.Insert(i, tempDic);
                    }

                }
                i++;
            }
            return TrimInput;
        }



        /* Response-Based Fuzz Testing */
        private static void RBFuzz(List<Dictionary<string, string>> oriInput)
        {
            /* Prepare work */
            List<Dictionary<string, string>> recordInput = new List<Dictionary<string, string>>();
            if (recordMode)
            {
                recordInput = ReadFromRecord(RecordFile, oriInput);

                if (recordInput != null)
                {
                    oriInput = recordInput;
                }


                Console.WriteLine("Response Type - Begin");
                for (int i = 0; i < ResponseTypeLibrary.Count; i++)
                {
                    Console.WriteLine("Index - " + i);
                    for (int j = 0; j < ResponseTypeLibrary[i].Count; j++)
                    {
                        Console.WriteLine("===============");
                        Console.WriteLine(ResponseTypeLibrary[i][j]);
                        Console.WriteLine("---------------");
                        Console.WriteLine(ResponseRandomnessList[i][j]);
                        Console.WriteLine("+++++++++++++++");
                    }
                    Console.WriteLine("Index - End");
                    Console.WriteLine('\n');

                }
                Console.WriteLine("\nResponse Type - End\n");

            }
            else
            {
                DryRun(oriInput);
            }

            /* Mutation */
            RBMutate(oriInput);
        }

        private static List<Dictionary<string, string>> ReadFromRecord(string recordFile, List<Dictionary<string, string>> oriInput)
        {
            List<Dictionary<string, string>> inputList = new List<Dictionary<string, string>>();
            Dictionary<string, string> input = new Dictionary<string, string>();
            inputList = oriInput;
            Boolean recordError = false;

            if (File.Exists(recordFile))
            {
                StreamReader sr = new StreamReader(recordFile, Encoding.UTF8);
                string line;
                while ((line = sr.ReadLine()) != null)
                {

                    if (fuzzMode == 1)
                    {
                        // Trim
                        if (line.StartsWith("Trim"))
                        {
                            while (!(line = sr.ReadLine()).StartsWith("Trim - End"))
                            {
                                if (line.Contains("===="))
                                {
                                    if (input.Count != 0)
                                    {
                                        inputList.Add(input);
                                    }
                                    input = new Dictionary<string, string>();
                                }

                                if (line.Contains(':'))
                                {
                                    string header;
                                    string content;
                                    header = line.Substring(0, line.IndexOf(':'));
                                    content = line.Substring(line.IndexOf(':') + 1, line.Length - line.IndexOf(':') - 1);

                                    input.Add(header, content);
                                    //Console.WriteLine(header+" --- "+content);
                                }
                            }
                            inputList.Add(input);
                        }

                        //Family Tree Generate
                        if (line.StartsWith("Family Tree Generate"))
                        {
                            /* Generate Family Tree */
                            FamilyTree = new List<TreeNode>();
                            for (int i = 0; i < inputList.Count; i++)
                            {
                                TreeNode node = new TreeNode();
                                node.index = i;
                                FamilyTree.Add(node);
                            }

                            /* Add node into Family Tree */
                            int index = 0;
                            while (!(line = sr.ReadLine()).StartsWith("Family Tree Generate - End"))
                            {
                                if (line.Contains("->"))
                                {
                                    string childrenStr = line.Substring(line.IndexOf("[") + 1, line.IndexOf("]") - line.IndexOf("[") - 1).Trim();
                                    if (!childrenStr.Contains("null"))
                                    {
                                        foreach (string o in childrenStr.Split(' ')) FamilyTree[index].children.Add(FamilyTree[Convert.ToInt32(o)]);
                                    }
                                    index++;
                                }
                            }
                        }
                    }


                    // Detection4Randomness
                    if (line.StartsWith("Detection4Randonmness"))
                    {
                        while (!(line = sr.ReadLine()).StartsWith("Detection4Randonmness - End"))
                        {
                            string[] compare = line.Trim().Split(' ');
                            if (compare.Length != inputList.Count) return null;
                            compareList = new List<double>();
                            try
                            {
                                foreach (string o in compare) compareList.Add(Convert.ToDouble(o));
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(" Detection4Randonmness Error: " + e.Message);
                                return null;
                            }
                        }
                    }

                    //First State
                    if (line.StartsWith("First Status"))
                    {
                        firstState = new List<List<int>>();
                        firstType = new List<List<int>>();

                        while (!(line = sr.ReadLine()).StartsWith("First Status - End"))
                        {
                            if (line.Contains("====="))
                            {
                                // skip three lines
                                line = sr.ReadLine();
                                line = sr.ReadLine();
                                line = sr.ReadLine();

                                if (fuzzMode == 1)
                                {
                                    // first state
                                    List<int> state = new List<int>();
                                    line = sr.ReadLine().Trim();
                                    string[] stateStr = line.Split(' ');
                                    foreach (string o in stateStr) state.Add(Convert.ToInt32(o));
                                    firstState.Add(state);
                                }

                                // first type
                                List<int> type = new List<int>();
                                line = sr.ReadLine().Trim();
                                string[] typeStr = line.Split(' ');
                                foreach (string o in typeStr) type.Add(Convert.ToInt32(o));
                                firstType.Add(type);
                            }
                        }
                    }

                    // Response Type
                    if (line.StartsWith("Response Type"))
                    {
                        ResponseTypeLibrary = new List<List<string>>();
                        ResponseRandomnessList = new List<List<double>>();

                        while (!(line = sr.ReadLine()).StartsWith("Response Type - End"))
                        {
                            if (line.Contains("Index - "))
                            {
                                List<string> typeList = new List<string>();
                                List<double> randomnessList = new List<double>();
                                while (!(line = sr.ReadLine()).StartsWith("Index - End"))
                                {
                                    if (line.StartsWith("======="))
                                    {
                                        string temResponse = "";
                                        string randomness = "";
                                        while (!(line = sr.ReadLine()).StartsWith("------"))
                                        {
                                            temResponse += line;
                                        }
                                        typeList.Add(temResponse);

                                        while (!(line = sr.ReadLine()).StartsWith("++++++"))
                                        {
                                            randomness = line.Trim();
                                        }
                                        randomnessList.Add(Convert.ToDouble(randomness));
                                    }
                                }
                                ResponseTypeLibrary.Add(typeList);
                                ResponseRandomnessList.Add(randomnessList);
                            }
                        }
                    }

                }

                sr.Close();
            }
            return inputList;
        }

        private static void RBMutate(List<Dictionary<string, string>> oriInput)
        {
            //List<string> res = controller.SendInputList(oriInput);


            /* Initialize the seed list and generate the first seed */
            List<string> res = controller.SendInputList(oriInput);
            Seed firstSeed = new Seed(oriInput, res, firstState, firstType);
            LoopSeedList = new SeedList(firstSeed);
            RecordSeedList = new SeedList(firstSeed);
            currentSeed = firstSeed;

            Random ran = new Random();


            int exectionTime = 0;
            string tFile = OutFold + DeviceName+"-"+ DateTime.Now.ToString("hh-mm-ss") + "-log.txt";
            FileStream oFileStream = new FileStream(tFile, FileMode.Create, FileAccess.Write);
            StreamWriter sw = new StreamWriter(oFileStream);
            sw.WriteLine("================== Log ===================");
            sw.Close();
            while (true)
            {
                // if there are some seeds 
                while (!LoopSeedList.isSeedListEmpty())
                {
                    Console.WriteLine("======= Times - " + exectionTime);
                    Console.WriteLine("+++ In Seed Loop\n");
                    exectionTime++;

                    /* Mutation */
                    for (int index = 0; index < currentSeed.Input.Count; index++) /* index loop */
                    {
                        Console.WriteLine("=========================================");
                        Console.WriteLine("------- index - " + index);

                        // Esco working on : need to change according to cluster 4/12
                        // =================================================  Cluster ==========================================
                        /* Cluster Level */
                        var metric = new DataPoint(null, null);
                        var dataPoints = new HashSet<DataPoint>();

                        /* Add feature vector to cluster*/
                        for (int j = 0; j < ResponseTypeLibrary[index].Count; j++)
                        {
                            int chr, num, sym;
                            chr = num = sym = 0;
                            StatisticRecord(ResponseTypeLibrary[index][j], ref chr, ref num, ref sym);
                            int length = ResponseTypeLibrary[index][j].Length;
                            Console.WriteLine(ResponseTypeLibrary[index][j]);
                            Console.WriteLine(j + " : Randoness - " + ResponseRandomnessList[index][j] + " length - " + length + " chr - " + chr + " num - " + num + " sym - " + sym);
                            dataPoints.Add(new DataPoint(Convert.ToString(j), new double[] { ResponseRandomnessList[index][j], length, chr, num, sym, }));
                        }

                        var perfMeasure = new PerformanceMeasure();
                        perfMeasure.Start();
                        var clusteringAlg = new AgglomerativeClusteringAlgorithm<DataPoint>(new AverageLinkage<DataPoint>(metric));
                        var clustering = clusteringAlg.GetClustering(dataPoints);
                        perfMeasure.Stop();

                        Console.WriteLine("_____________________________________________");
                        Console.WriteLine("Average");
                        Console.WriteLine(perfMeasure);

                        foreach (var clusterSet in clustering)
                        {
                            Console.WriteLine($"Clusters at distance: {clusterSet.Dissimilarity:0.00} ({clusterSet.Count})");
                            foreach (var cluster in clusterSet)
                                Console.WriteLine($" - {cluster}");
                        }

                        string name = "average";

                        clustering.SaveD3DendrogramFile(Path.GetFullPath($"{name}.json"), formatting: Formatting.Indented);


                        List<Dictionary<int, string>> fieldList = new List<Dictionary<int, string>>();
                        Dictionary<int, string> field = new Dictionary<int, string>();
                        foreach (var clusterSet in clustering) // =========================== Cluster Loop ==================================
                        {
                            //if (clusterSet.Dissimilarity > 5.00) break; /* do not want to try */

                            List<int> ClusterType = new List<int>();
                            int[] convertTemp = new int[ResponseTypeLibrary[index].Count];  // original index -> index after cluster

                            Console.WriteLine($"Clusters at distance: {clusterSet.Dissimilarity:0.00} ({clusterSet.Count})");
                            int o = 0;
                            foreach (var cluster in clusterSet)
                            {
                                string clusterGroup = $"{cluster}";
                                clusterGroup = clusterGroup.Remove(0, 1);
                                clusterGroup = clusterGroup.Remove(clusterGroup.Length - 1, 1);
                                Console.WriteLine(clusterGroup);
                                if (clusterGroup.Contains(';'))
                                {
                                    foreach (var v in clusterGroup.Split(';'))
                                    {
                                        convertTemp[Convert.ToInt32(v)] = o;
                                    }
                                }
                                else
                                {
                                    convertTemp[Convert.ToInt32(clusterGroup)] = o;
                                }
                                o++;
                            }


                            Console.WriteLine(currentSeed.Input[index]["Content"]);
                            Console.WriteLine();
                            foreach (var v in currentSeed.Types[index]) Console.Write(v);
                            Console.WriteLine();
                            Console.WriteLine();

                            for (int n = 0; n < currentSeed.Input[index]["Content"].Length; n++)
                            {
                                ClusterType.Add(convertTemp[currentSeed.Types[index][n]]);
                                Console.Write(ClusterType[n]);
                            }
                            Console.WriteLine();
                            Console.WriteLine();


                            /* code segment   start - end */
                            int segStart = 0;
                            int segEnd = 0;
                            while (segStart < currentSeed.Input[index]["Content"].Length) /* segments loop */
                            {

                                /* split the content by states and types and find segment*/
                                Boolean changeFlag = false;
                                for (int j = segStart; j < currentSeed.Input[index]["Content"].Length; j++)
                                {
                                    if (fuzzMode == 1)
                                    {
                                        if (ClusterType[j] != ClusterType[segStart] ||
                                        currentSeed.States[index][j] != currentSeed.States[index][segStart])
                                        {
                                            segEnd = j;
                                            changeFlag = true;
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        if (ClusterType[j] != ClusterType[segStart])
                                        {
                                            segEnd = j;
                                            changeFlag = true;
                                            break;
                                        }
                                    }
                                    if (!changeFlag) segEnd = currentSeed.Input[index]["Content"].Length - 1;


                                }
                                Console.WriteLine("------ - index - " + index + "  ````` segStart - " + segStart + "  segEnd - " + segEnd + "  seg - " + currentSeed.Input[index]["Content"].Substring(segStart, segEnd - segStart));
                                FileStream oS = new FileStream(tFile, FileMode.Append, FileAccess.Write);
                                StreamWriter oSW = new StreamWriter(oS);
                                oSW.WriteLine("------ - index - " + index + "  ````` segStart - " + segStart + "  segEnd - " + segEnd + "  seg - " + currentSeed.Input[index]["Content"].Substring(segStart, segEnd - segStart)+"\t\t"+ DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                                oSW.Close();


                                field = new Dictionary<int, string>();
                                field.Add(segStart, currentSeed.Input[index]["Content"].Substring(segStart, segEnd - segStart));

                                Boolean skipFlag = false;
                                foreach (var f in fieldList)
                                {
                                    foreach (var d in f)
                                    {
                                        if (d.Key.Equals(segStart) && d.Value.Equals(currentSeed.Input[index]["Content"].Substring(segStart, segEnd - segStart)))
                                        {
                                            skipFlag = true;
                                            break;
                                        }
                                    }
                                    if (skipFlag) break;
                                }

                                if (skipFlag)
                                {
                                    Console.WriteLine("+++++++++++++++++++");
                                    Console.WriteLine("Skip ------- index - " + index + "  ````` segStart - " + segStart + "  segEnd - " + segEnd + "  seg - " + currentSeed.Input[index]["Content"].Substring(segStart, segEnd - segStart));

                                    if (segEnd != currentSeed.Input[index]["Content"].Length - 1)
                                    {
                                        segStart = segEnd;
                                    }
                                    else
                                    {
                                        segStart = currentSeed.Input[index]["Content"].Length;
                                    }
                                    continue;
                                }
                                else
                                {
                                    fieldList.Add(field);
                                }

                                Console.WriteLine("+++++++++++++++++++");
                                Console.WriteLine("");
                                foreach (var f in fieldList)
                                {

                                    foreach (var d in f)
                                    {
                                        Console.Write(d.Key + "  ");
                                        Console.WriteLine(d.Value);
                                    }
                                }
                                Console.WriteLine("++++++++++++++++++++");


                                string tempContent = "";
                                string tempStr = "";
                                List<string> response = new List<string>();

                                /* mutate the segment */
                                if (fuzzMode == 1)  // fuzzMode == 1
                                {
                                    switch (currentSeed.States[index][segStart])
                                    {
                                        case 1:
                                            /* Skip the server reject result */
                                            break;
                                        case 2:

                                            /* ====================== Empty ===================== */
                                            /* empty the segment to check wheather they are Impurities */
                                            tempContent = currentSeed.Input[index]["Content"];
                                            currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Remove(segStart, segEnd - segStart);
                                            Console.WriteLine(currentSeed.Input[index]["Content"]);
                                            response = controller.SendInputList(currentSeed.Input);
                                            if (response == null) break;
                                            /* analyse the result and save the seed if it`s interesting*/
                                            if (AnalyseResult(response))
                                            {
                                                SaveAsSeed(currentSeed.Input, response, index, currentSeed.States, currentSeed.Types);
                                            }
                                            /* restore the seed input */
                                            currentSeed.Input[index]["Content"] = tempContent;

                                            break;
                                        case 3:

                                            Boolean breakFlag = false;
                                            /* ====================== Data Boundry ===================== */
                                            tempContent = currentSeed.Input[index]["Content"];
                                            string seg = currentSeed.Input[index]["Content"].Substring(segStart, segEnd - segStart);
                                            if (IsNumeric(seg))
                                            {
                                                foreach (string[] test in TestInt)
                                                {
                                                    breakFlag = false;
                                                    foreach (string str in test)
                                                    {
                                                        currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Remove(segStart, segEnd - segStart);
                                                        currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Insert(segStart, str);
                                                        Console.WriteLine(currentSeed.Input[index]["Content"]);
                                                        response = controller.SendInputList(currentSeed.Input);
                                                        if (response == null) break;
                                                        /* analyse the result and save the seed if it`s interesting*/
                                                        if (AnalyseResult(response))
                                                        {
                                                            SaveAsSeed(currentSeed.Input, response, index, currentSeed.States, currentSeed.Types);
                                                            breakFlag = true;
                                                        }
                                                        /* restore the seed input */
                                                        currentSeed.Input[index]["Content"] = tempContent;
                                                    }
                                                    if (breakFlag) break;
                                                }
                                            }

                                            /* ====================== Data Dictionary ===================== */
                                            tempContent = currentSeed.Input[index]["Content"];

                                            foreach (string str in InterestingValue)
                                            {
                                                currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Remove(segStart, segEnd - segStart);
                                                currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Insert(segStart, str);
                                                Console.WriteLine(currentSeed.Input[index]["Content"]);
                                                response = controller.SendInputList(currentSeed.Input);
                                                if (response == null) break;
                                                /* analyse the result and save the seed if it`s interesting*/
                                                if (AnalyseResult(response))
                                                {
                                                    SaveAsSeed(currentSeed.Input, response, index, currentSeed.States, currentSeed.Types);
                                                }
                                                /* restore the seed input */
                                                currentSeed.Input[index]["Content"] = tempContent;
                                            }
                                            break;
                                        default:
                                            break;
                                    }
                                }
                                else   // fuzzMode != 1
                                {
                                    Boolean breakFlag = false;

                                    /* ====================== Empty ===================== */
                                    /* empty the segment to check wheather they are Impurities */
                                    Console.WriteLine("*** Phase - Empty ");
                                    tempContent = currentSeed.Input[index]["Content"];
                                    currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Remove(segStart, segEnd - segStart);
                                    Console.WriteLine(currentSeed.Input[index]["Content"]);
                                    response = controller.SendInputList(currentSeed.Input);
                                    
                                    if (response == null) break;
                                    oSW = new StreamWriter(oS);
                                    oSW.WriteLine(response);
                                    oSW.Close();
                                    /* analyse the result and save the seed if it`s interesting*/
                                    if (AnalyseResult(response))
                                    {
                                        SaveAsSeed(currentSeed.Input, response, index, currentSeed.States, currentSeed.Types);
                                    }
                                    /* restore the seed input */
                                    currentSeed.Input[index]["Content"] = tempContent;


                                    /* ====================== Data Boundry ===================== */
                                    Console.WriteLine("*** Phase - Boundry ");
                                    tempContent = currentSeed.Input[index]["Content"];
                                    string seg = currentSeed.Input[index]["Content"].Substring(segStart, segEnd - segStart);
                                    if (IsNumeric(seg))
                                    {
                                        foreach (string[] test in TestInt)
                                        {
                                            breakFlag = false;
                                            foreach (string str in test)
                                            {
                                                currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Remove(segStart, segEnd - segStart);
                                                currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Insert(segStart, str);
                                                Console.WriteLine(currentSeed.Input[index]["Content"]);
                                                response = controller.SendInputList(currentSeed.Input);
                                                oSW.WriteLine(response);
                                                if (response == null) break;
                                                /* analyse the result and save the seed if it`s interesting*/
                                                if (AnalyseResult(response))
                                                {
                                                    SaveAsSeed(currentSeed.Input, response, index, currentSeed.States, currentSeed.Types);
                                                    breakFlag = true;
                                                }
                                                /* restore the seed input */
                                                currentSeed.Input[index]["Content"] = tempContent;
                                            }
                                            if (breakFlag) break;
                                        }
                                    }


                                    /* ====================== Data Dictionary ===================== */
                                    Console.WriteLine("*** Phase - Dictionary ");
                                    tempContent = currentSeed.Input[index]["Content"];

                                    foreach (string str in InterestingValue)
                                    {
                                        currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Remove(segStart, segEnd - segStart);
                                        currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Insert(segStart, str);
                                        //Console.WriteLine(currentSeed.Input[index]["Content"]);
                                        response = controller.SendInputList(currentSeed.Input);
                                        if (response == null) break;
                                        oSW = new StreamWriter(oS);
                                        oSW.WriteLine(response);
                                        oSW.Close();
                                        /* analyse the result and save the seed if it`s interesting*/
                                        if (AnalyseResult(response))
                                        {
                                            SaveAsSeed(currentSeed.Input, response, index, currentSeed.States, currentSeed.Types);
                                        }
                                        /* restore the seed input */
                                        currentSeed.Input[index]["Content"] = tempContent;
                                    }

                                    /* ====================== Bit Flip ===================== 
                                    Console.WriteLine("*** Phase - Bit Flip ");
                                    tempContent = currentSeed.Input[index]["Content"];

                                    for (int i = 0; i < segEnd - segStart; i++)
                                    {
                                        byte[] BitContent = Encoding.Default.GetBytes(currentSeed.Input[index]["Content"]);
                                        BitContent[segStart + i] = (byte)~BitContent[segStart + i];
                                        currentSeed.Input[index]["Content"] = Encoding.Default.GetString(BitContent);
                                        //Console.WriteLine(currentSeed.Input[index]["Content"]);
                                        response = controller.SendInputList(currentSeed.Input);
                                        /* analyse the result and save the seed if it`s interesting
                                        if (AnalyseResult(response))
                                        {
                                            SaveAsSeed(currentSeed.Input, response, index, currentSeed.States, currentSeed.Types);
                                        }
                                        /* restore the seed input 
                                        currentSeed.Input[index]["Content"] = tempContent;
                                    }
                                    */


                                    /* ====================== Bits Flip ===================== */
                                    Console.WriteLine("*** Phase - Bits Flip ");
                                    tempContent = currentSeed.Input[index]["Content"];

                                    byte[] BitsContent = Encoding.Default.GetBytes(currentSeed.Input[index]["Content"]);
                                    for (int i = 0; i < segEnd - segStart; i++)
                                    {
                                        BitsContent[segStart + i] = (byte)~BitsContent[segStart + i];
                                    }
                                    currentSeed.Input[index]["Content"] = Encoding.Default.GetString(BitsContent);
                                    //Console.WriteLine(currentSeed.Input[index]["Content"]);
                                    response = controller.SendInputList(currentSeed.Input);

                                    if (response == null) break;
                                    oSW = new StreamWriter(oS);
                                    oSW.WriteLine(response);
                                    oSW.Close();
                                    /* analyse the result and save the seed if it`s interesting*/
                                    if (AnalyseResult(response))
                                    {
                                        SaveAsSeed(currentSeed.Input, response, index, currentSeed.States, currentSeed.Types);
                                    }
                                    /* restore the seed input */
                                    currentSeed.Input[index]["Content"] = tempContent;


                                    /* ====================== Repeat ===================== */
                                    Console.WriteLine("*** Phase - Repeat ");
                                    tempContent = currentSeed.Input[index]["Content"];

                                    currentSeed.Input[index]["Content"] = currentSeed.Input[index]["Content"].Insert(segStart, currentSeed.Input[index]["Content"].Substring(segStart, segEnd - segStart));

                                    //Console.WriteLine(currentSeed.Input[index]["Content"]);
                                    response = controller.SendInputList(currentSeed.Input);
                                    if (response == null) break;
                                    oSW = new StreamWriter(oS);
                                    oSW.WriteLine(response);
                                    oSW.Close();
                                    /* analyse the result and save the seed if it`s interesting*/
                                    if (AnalyseResult(response))
                                    {
                                        SaveAsSeed(currentSeed.Input, response, index, currentSeed.States, currentSeed.Types);
                                    }
                                    /* restore the seed input */
                                    currentSeed.Input[index]["Content"] = tempContent;

                                }

                                if (segEnd != currentSeed.Input[index]["Content"].Length - 1)
                                {
                                    segStart = segEnd;
                                }
                                else
                                {
                                    segStart = currentSeed.Input[index]["Content"].Length;
                                }

                            }


                        }



                    }


                    /* next input in seed list */
                    currentSeed = LoopSeedList.pickNext(currentSeed);
                }

                Console.WriteLine("Times - " + exectionTime);
                Console.WriteLine("+++ In Havoc\n");
                

                exectionTime++;

                // there is no inputs -> havoc
                currentSeed = RecordSeedList.seeds[ran.Next(0, RecordSeedList.seeds.Count - 1)];

                //int times = ran.Next(0, 2);
                //for(int time = 0; time < times; time++)
                int pick = ran.Next(0, 5);
                switch (pick)
                {
                    case 0: /* Replace Bytes To Interesting Value */
                        Console.WriteLine("``````` Case 0 Replace Bytes To Interesting Value");

                        int o = ran.Next(0, currentSeed.Input.Count - 1);
                        string tempContent = currentSeed.Input[o]["Content"];
                        int start = ran.Next(0, currentSeed.Input[o]["Content"].Length - 2);
                        int end = ran.Next(start + 1, currentSeed.Input[o]["Content"].Length - 1);

                        Console.WriteLine("````` segStart - " + start + "  segEnd - " + end + "  seg - " + currentSeed.Input[o]["Content"].Substring(start, end - start));


                        string str = InterestingValue[ran.Next(0, InterestingValue.Count)];

                        currentSeed.Input[o]["Content"] = currentSeed.Input[o]["Content"].Remove(start, end - start);
                        currentSeed.Input[o]["Content"] = currentSeed.Input[o]["Content"].Insert(start, str);
                        List<string> response = controller.SendInputList(currentSeed.Input);
                        if (response == null) break;
                        Console.WriteLine(currentSeed.Input[o]["Content"]);

                        FileStream oStream = new FileStream(tFile, FileMode.Append, FileAccess.Write);
                        StreamWriter oSw = new StreamWriter(oStream);
                        oSw.WriteLine("+++ In Havoc  " + "Times - " + exectionTime + "\t\t" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                        oSw.WriteLine(currentSeed.Input[o]["Content"]);
                        oSw.Close();

                        /* analyse the result and save the seed if it`s interesting*/
                        if (AnalyseResult(response))
                        {
                            SaveAsSeed(currentSeed.Input, response, o, currentSeed.States, currentSeed.Types);
                        }
                        /* restore the seed input */
                        currentSeed.Input[o]["Content"] = tempContent;

                        break;
                    case 1: /* Randomly Subtract */
                        Console.WriteLine("``````` Case 1 Randomly Subtract");

                        o = ran.Next(0, currentSeed.Input.Count - 1);
                        tempContent = currentSeed.Input[o]["Content"];
                        start = ran.Next(0, currentSeed.Input[o]["Content"].Length - 2);
                        end = ran.Next(start + 1, currentSeed.Input[o]["Content"].Length - 1);
                        Console.WriteLine("````` segStart - " + start + "  segEnd - " + end + "  seg - " + currentSeed.Input[o]["Content"].Substring(start, end - start));

                        currentSeed.Input[o]["Content"] = currentSeed.Input[o]["Content"].Remove(start, end - start);
                        Console.WriteLine(currentSeed.Input[o]["Content"]);
                        response = controller.SendInputList(currentSeed.Input);
                        if (response == null) break;

                        oStream = new FileStream(tFile, FileMode.Append, FileAccess.Write);
                        oSw = new StreamWriter(oStream);
                        oSw.WriteLine("+++ In Havoc  " + "Times - " + exectionTime + "\t\t" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                        oSw.WriteLine(currentSeed.Input[o]["Content"]);
                        oSw.Close();

                        /* analyse the result and save the seed if it`s interesting*/
                        if (AnalyseResult(response))
                        {
                            SaveAsSeed(currentSeed.Input, response, o, currentSeed.States, currentSeed.Types);
                        }
                        /* restore the seed input */
                        currentSeed.Input[o]["Content"] = tempContent;

                        break;
                    case 2: /* Randomly Repeat */
                        Console.WriteLine("``````` Case 2 Randomly Repeat ");
                        o = ran.Next(0, currentSeed.Input.Count - 1);
                        tempContent = currentSeed.Input[o]["Content"];
                        start = ran.Next(0, currentSeed.Input[o]["Content"].Length - 2);
                        end = ran.Next(start + 1, currentSeed.Input[o]["Content"].Length - 1);
                        Console.WriteLine("````` segStart - " + start + "  segEnd - " + end + "  seg - " + currentSeed.Input[o]["Content"].Substring(start, end - start));
                        currentSeed.Input[o]["Content"] = currentSeed.Input[o]["Content"].Insert(start, currentSeed.Input[o]["Content"].Substring(start, end - start));
                        Console.WriteLine(currentSeed.Input[o]["Content"]);
                        response = controller.SendInputList(currentSeed.Input);
                        if (response == null) break;

                        oStream = new FileStream(tFile, FileMode.Append, FileAccess.Write);
                        oSw = new StreamWriter(oStream);
                        oSw.WriteLine("+++ In Havoc  " + "Times - " + exectionTime + "\t\t" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                        oSw.WriteLine(currentSeed.Input[o]["Content"]);
                        oSw.Close();

                        /* analyse the result and save the seed if it`s interesting*/
                        if (AnalyseResult(response))
                        {
                            SaveAsSeed(currentSeed.Input, response, o, currentSeed.States, currentSeed.Types);
                        }
                        /* restore the seed input */
                        currentSeed.Input[o]["Content"] = tempContent;
                        break;

                    case 3: /* Flip a single bit */
                        Console.WriteLine("``````` Case 3 Flip a single bit");

                        o = ran.Next(0, currentSeed.Input.Count - 1);
                        tempContent = currentSeed.Input[o]["Content"];
                        start = ran.Next(0, currentSeed.Input[o]["Content"].Length - 2);
                        end = start + 1;

                        Console.WriteLine("````` byte - " + currentSeed.Input[o]["Content"].Substring(start, 1));
                        byte[] content = Encoding.Default.GetBytes(currentSeed.Input[o]["Content"]);
                        content[start] = (byte)~content[start];
                        currentSeed.Input[o]["Content"] = Encoding.Default.GetString(content);

                        Console.WriteLine(currentSeed.Input[o]["Content"]);
                        response = controller.SendInputList(currentSeed.Input);
                        if (response == null) break;

                        oStream = new FileStream(tFile, FileMode.Append, FileAccess.Write);
                        oSw = new StreamWriter(oStream);
                        oSw.WriteLine("+++ In Havoc  " + "Times - " + exectionTime + "\t\t" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                        oSw.WriteLine(currentSeed.Input[o]["Content"]);
                        oSw.Close();

                        /* analyse the result and save the seed if it`s interesting*/
                        if (AnalyseResult(response))
                        {
                            SaveAsSeed(currentSeed.Input, response, o, currentSeed.States, currentSeed.Types);
                        }
                        /* restore the seed input */
                        currentSeed.Input[o]["Content"] = tempContent;
                        break;
                    case 4: /* Flip Bits */
                        Console.WriteLine("``````` Case 4 Flip Bits ");

                        o = ran.Next(0, currentSeed.Input.Count - 1);
                        tempContent = currentSeed.Input[o]["Content"];
                        start = ran.Next(0, currentSeed.Input[o]["Content"].Length - 2);
                        end = ran.Next(start + 1, currentSeed.Input[o]["Content"].Length - 1);

                        Console.WriteLine("````` byte - " + currentSeed.Input[o]["Content"].Substring(start, end - start));
                        content = Encoding.Default.GetBytes(currentSeed.Input[o]["Content"]);
                        for (int t = start; t < end; t++)
                        {
                            content[t] = (byte)~content[t];
                        }
                        currentSeed.Input[o]["Content"] = Encoding.Default.GetString(content);

                        Console.WriteLine(currentSeed.Input[o]["Content"]);
                        response = controller.SendInputList(currentSeed.Input);
                        if (response == null) break;

                        oStream = new FileStream(tFile, FileMode.Append, FileAccess.Write);
                        oSw = new StreamWriter(oStream);
                        oSw.WriteLine("+++ In Havoc  " + "Times - " + exectionTime + "\t\t" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                        oSw.WriteLine(currentSeed.Input[o]["Content"]);
                        oSw.Close();

                        /* analyse the result and save the seed if it`s interesting*/
                        if (AnalyseResult(response))
                        {
                            SaveAsSeed(currentSeed.Input, response, o, currentSeed.States, currentSeed.Types);
                        }
                        /* restore the seed input */
                        currentSeed.Input[o]["Content"] = tempContent;
                        break;
                    case 5:
                        break;
                    default:
                        break;
                }






            }

        }

        private static void ResponseLibraryInitialization(List<Dictionary<string, string>> oriInput, ref List<List<int>> state, ref List<List<int>> type)
        {
            currentStep = "ResponseLibraryInitialization";

            // initialize 
            /* Response Feature */
            List<List<int>> responseTypeRecord = new List<List<int>>();
            List<List<int>> NetStates = new List<List<int>>();

            /* Response List */
            List<List<double>> randomness = new List<List<double>>();
            ResponseRandomnessList = new List<List<double>>();
            ResponseTypeLibrary = new List<List<string>>();

            /* initialize input message sequence */
            List<Dictionary<string, string>> tempInput = new List<Dictionary<string, string>>();
            foreach (Dictionary<string, string> input in oriInput) tempInput.Add(input);

            /* Record the original message features and initialize the record vars */
            List<string> FirstResponseList = controller.SendInputList(oriInput);
            //Thread.Sleep(100);
            List<string> SecondResponseList = controller.SendInputList(oriInput);
            for (int i = 0; i < Math.Max(FirstResponseList.Count, SecondResponseList.Count); i++)
            {
                /* Randomness record */
                List<double> r = new List<double>();
                r.Add(CompareStrings(FirstResponseList[i], SecondResponseList[i]));
                ResponseRandomnessList.Add(r);

                /* Response record */
                List<string> p = new List<string>();
                p.Add(FirstResponseList[i]);
                ResponseTypeLibrary.Add(p);

                /* Longest Substring record */
                //List<string> l = new List<string>();
                //l.Add("");
                //longestSub.Add(l);


                /* Network State record */
                if (fuzzMode == 1)
                {
                    List<int> o = new List<int>();
                    o.Add(0);
                    NetStates.Add(o);
                }

            }


            // Test only ----- i < 1
            // Record detection message`s features
            for (int i = 0; i < oriInput.Count; i++)
            //for (int i = 0; i < 1; i++)
            {
                string tempString = tempInput[i]["Content"];   // for restore messages
                List<int> responseTpye = new List<int>();
                Console.WriteLine(tempString);

                for (int index = 0; index < tempInput[i]["Content"].Length; index++)  // delete a single char to generate a detection message
                {
                    string str = tempInput[i]["Content"];
                    string tempstr = tempInput[i]["Content"];
                    str = str.Remove(index, 1);
                    tempInput[i]["Content"] = str;

                    FirstResponseList = controller.SendInputList(tempInput);
                    //Thread.Sleep(100);
                    SecondResponseList = controller.SendInputList(tempInput);

                    bool newRes = true;

                    // Esco: maybe need to change to without the Randomness check
                    for (int t = 0; t < ResponseTypeLibrary[i].Count; t++)
                    {
                        if (CompareResponses(ResponseRandomnessList[i][t], ResponseTypeLibrary[i][t], FirstResponseList[i]))
                        {
                            newRes = false;
                            /* Response type record*/
                            responseTpye.Add(t);
                            break;
                        }
                    }
                    if (newRes)
                    {
                        /* Randomness record */
                        ResponseRandomnessList[i].Add(CompareStrings(FirstResponseList[i], SecondResponseList[i]));
                        /* Response record */
                        ResponseTypeLibrary[i].Add(FirstResponseList[i]);
                        /* Response type record*/
                        responseTpye.Add(ResponseTypeLibrary[i].IndexOf(FirstResponseList[i]));
                    }

                    Console.Write(responseTpye[index]);

                    /* Longest Substring record */
                    //longestSub[i].Add("");

                    /* Network State record */
                    if (fuzzMode == 1)
                    {
                        NetStates[i].Add(0);
                    }

                    // restore
                    tempInput[i]["Content"] = tempstr;
                }

                responseTypeRecord.Add(responseTpye);
                Console.WriteLine();
            }

            state = NetStates;
            type = responseTypeRecord;
        }

        private static void StatisticRecord(string v, ref int chr, ref int num, ref int sym)
        {
            chr = num = sym = 0;
            int start = 0;
            int end = 0;
            v = v.ToLower();
            string current = "chr";


            while (start < v.Length)
            {
                /* Determine the current character`s type */
                if (Convert.ToInt32(v[start]) > 47 && Convert.ToInt32(v[start]) < 58)
                {
                    current = "num";
                    num++;
                }
                else if (Convert.ToInt32(v[start]) > 96 && Convert.ToInt32(v[start]) < 123)
                {
                    current = "chr";
                    chr++;
                }
                else
                {
                    current = "sym";
                    sym++;
                }

                /* Determine the following characters` type */
                end = start + 1;
                bool same = true;
                while (end < v.Length)
                {
                    switch (current)
                    {
                        case "num":
                            if (Convert.ToInt32(v[end]) < 47 || Convert.ToInt32(v[end]) > 58) same = false;
                            break;
                        case "chr":
                            if (Convert.ToInt32(v[end]) < 96 || Convert.ToInt32(v[end]) > 123) same = false;
                            break;
                        case "sym":
                            if ((Convert.ToInt32(v[end]) > 47 && Convert.ToInt32(v[end]) < 58) || (Convert.ToInt32(v[end]) > 96 && Convert.ToInt32(v[end]) < 123)) same = false;
                            break;
                        default:
                            same = false;
                            break;
                    }

                    if (!same) break;
                    end++;
                }
                start = end;
            }
        }


        private static void SaveAsSeed(List<Dictionary<string, string>> inputs, List<string> oResponse, int oIndex, List<List<int>> oldStates, List<List<int>> oldTypes)
        {
            currentStep = "SaveAsSeed";

            // initialize 
            /* Response Feature */
            List<List<int>> states = new List<List<int>>();
            List<List<int>> type = new List<List<int>>();

            /* initialize input message sequence */
            List<Dictionary<string, string>> tempInput = new List<Dictionary<string, string>>();
            foreach (Dictionary<string, string> input in inputs) tempInput.Add(input);

            /* Record the original message features and initialize the record vars */
            List<string> FirstResponseList = controller.SendInputList(inputs);
            //Thread.Sleep(100);
            List<string> SecondResponseList = controller.SendInputList(inputs);

            for (int i = 0; i < Math.Max(FirstResponseList.Count, SecondResponseList.Count); i++)
            {
                bool newRes = true;
                for (int t = 0; t < ResponseTypeLibrary[i].Count; t++)
                {
                    if (CompareResponses(ResponseRandomnessList[i][t], ResponseTypeLibrary[i][t], FirstResponseList[i]))
                    {
                        newRes = false;
                        break;
                    }
                }
                if (newRes)
                {
                    /* Randomness record */
                    ResponseRandomnessList[i].Add(CompareStrings(FirstResponseList[i], SecondResponseList[i]));
                    /* Response record */
                    ResponseTypeLibrary[i].Add(FirstResponseList[i]);
                }

            }

            // Inherit the attributes of the previous message
            for (int i = 0; i < oIndex; i++)
            {
                states.Add(oldStates[i]);
                type.Add(oldTypes[i]);
            }


            // Record detection message`s features
            for (int i = oIndex; i < inputs.Count; i++)  //  Only test subsequent messages
            {
                string tempString = tempInput[i]["Content"];   // for restore messages
                List<int> responseTpye = new List<int>();
                Console.WriteLine(tempString);

                for (int index = 0; index < tempInput[i]["Content"].Length; index++)  // delete a single char to generate a detection message
                {
                    string str = tempInput[i]["Content"];
                    string tempstr = tempInput[i]["Content"];
                    str = str.Remove(index, 1);
                    tempInput[i]["Content"] = str;

                    FirstResponseList = controller.SendInputList(tempInput);
                    //Thread.Sleep(100);
                    SecondResponseList = controller.SendInputList(tempInput);

                    bool newRes = true;

                    // Esco: maybe need to change to without the Randomness check
                    for (int t = 0; t < ResponseTypeLibrary[i].Count; t++)
                    {
                        if (CompareResponses(ResponseRandomnessList[i][t], ResponseTypeLibrary[i][t], FirstResponseList[i]))
                        {
                            newRes = false;
                            /* Response type record*/
                            responseTpye.Add(t);
                            break;
                        }
                    }
                    if (newRes)
                    {
                        /* Randomness record */
                        ResponseRandomnessList[i].Add(CompareStrings(FirstResponseList[i], SecondResponseList[i]));
                        /* Response record */
                        ResponseTypeLibrary[i].Add(FirstResponseList[i]);
                        /* Response type record*/
                        responseTpye.Add(ResponseTypeLibrary[i].IndexOf(FirstResponseList[i]));
                    }

                    Console.Write(responseTpye[index]);

                    /* Longest Substring record */
                    //longestSub[i].Add("");

                    /* Network State record */
                    if (fuzzMode == 1)
                    {
                        states[i].Add(0);
                    }

                    // restore
                    tempInput[i]["Content"] = tempstr;
                }

                type.Add(responseTpye);
                Console.WriteLine();
            }


            /* create the new seed and save the seed in record and loop list */
            Seed newSeed = new Seed(inputs, oResponse, states, type);
            LoopSeedList.seeds.Add(newSeed);
            RecordSeedList.seeds.Add(newSeed);

        }

        // Esco : consider wheather change the jugdement of new responses
        private static bool AnalyseResult(List<string> response)
        {
            /* number of responses doesn`t match */
            if (response == null) return true;
            if (ResponseTypeLibrary.Count != response.Count) return true;

            /* is there a new response */
            for (int i = 1; i < response.Count; i++)
            {
                Boolean flag = false;
                for (int t = 0; t < ResponseTypeLibrary[i].Count; t++)
                {
                    if (CompareResponses(ResponseRandomnessList[i][t], ResponseTypeLibrary[i][t], response[i]))
                    {
                        flag = true;
                        break;
                    }
                }
                if (!flag)
                {
                    return false;
                }
            }

            return false;
        }

        private static void DumbFuzz(List<Dictionary<string, string>> oriInput)
        {
            currentStep = "DumbFuzz";
            LinkedList<List<Dictionary<string, string>>> interestedInputList = new LinkedList<List<Dictionary<string, string>>>();
            interestedInputList.AddFirst(oriInput);

            /* Mutation */

            DumbMutate(oriInput);

        }

        private static void DumbMutate(List<Dictionary<string, string>> input)
        {
            string stage_name;
            List<string> response = new List<string>();
            List<Dictionary<string, string>> nInput = new List<Dictionary<string, string>>(input);

            /* In the Dumb mode we present the traditional mutation strategy (used in AFL)
            
            * Deterministic :      1)  Bitflip
                *                  2)  Dictionary
                *                  3)  Stack
                *                  4)  Empty
                */

            /* Bitflip */
            stage_name = "Bitflip 1 - 1";

            for (int i = 0; i < input.Count; i++)
            {
                string oriContent = input[i]["Content"];
                for (int index = 0; index < input[i]["Content"].Length; index++)
                {
                    byte[] content = Encoding.Default.GetBytes(input[i]["Content"]);
                    /* bit flip */
                    content[index] = (byte)~content[index];
                    nInput[i]["Content"] = Encoding.Default.GetString(content);

                    //Console.WriteLine(nInput[i]["Content"]);
                    response = controller.SendInputList(nInput);

                    /* restore */
                    nInput[i]["Content"] = oriContent;
                }
                //Console.WriteLine(input[i]["Content"]);
                //Console.WriteLine();
            }

            /* Dictionary */
            stage_name = "Dictionary 1 - 1";

            List<string> dict = new List<string>();
            dict = ReadDictionary(DictionaryFile);

            if (dict.Count != 0)
            {
                for (int i = 0; i < input.Count; i++)
                {
                    string oriContent = input[i]["Content"];
                    for (int index = 0; index < input[i]["Content"].Length; index++)
                    {
                        for (int n = 0; n < dict.Count; n++)
                        {
                            /* replace char with word in dictionary */
                            string content = input[i]["Content"];
                            content = content.Remove(index, 1);
                            content = content.Insert(index, dict[n]);
                            nInput[i]["Content"] = content;

                            Console.WriteLine(nInput[i]["Content"]);
                            //response = SendInputList(nInput);

                            /* restore */
                            nInput[i]["Content"] = oriContent;
                        }

                    }
                }
            }

            /* Stack */
            stage_name = "Stack 1 - 1";

            for (int i = 0; i < input.Count; i++)
            {
                string oriContent = input[i]["Content"];
                for (int index = 0; index < input[i]["Content"].Length; index++)
                {
                    string content = input[i]["Content"];
                    /* stack */
                    content = content.Insert(index, content.Substring(index, 1));
                    nInput[i]["Content"] = content;

                    //Console.WriteLine(nInput[i]["Content"]);
                    response = controller.SendInputList(nInput);

                    /* restore */
                    nInput[i]["Content"] = oriContent;
                }
                //Console.WriteLine(input[i]["Content"]);
                //Console.WriteLine();
            }

            /* Empty */
            stage_name = "Empty 1 - 1";

            for (int i = 0; i < input.Count; i++)
            {
                string oriContent = input[i]["Content"];
                for (int index = 0; index < input[i]["Content"].Length; index++)
                {
                    string content = input[i]["Content"];
                    /* stack */
                    content = content.Remove(index, 1);
                    nInput[i]["Content"] = content;

                    //Console.WriteLine(nInput[i]["Content"]);
                    response = controller.SendInputList(nInput);

                    /* restore */
                    nInput[i]["Content"] = oriContent;
                }
                //Console.WriteLine(input[i]["Content"]);
                //Console.WriteLine();
            }




        }

        private static List<string> ReadDictionary(string dictionaryFile)
        {
            List<string> dict = new List<string>();
            if (File.Exists(dictionaryFile))
            {
                StreamReader sr = new StreamReader(dictionaryFile, Encoding.UTF8);
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    dict.Add(line);
                    Console.WriteLine(line);
                }
                sr.Close();
            }
            return dict;
        }

        private static List<int[]> ProtocolAllocate(List<Dictionary<string, string>> oriInput)
        {
            currentStep = "ProtocolAllocate";
            List<Dictionary<string, string>> inputList = new List<Dictionary<string, string>>();
            List<string> res = new List<string>();
            List<int> hashMap = new List<int>();
            List<List<string>> resList = new List<List<string>>();
            List<int[]> typeMap = new List<int[]>();
            foreach (Dictionary<string, string> input in oriInput) inputList.Add(input);

            // Allocate protocol 
            for (int i = 1; i < oriInput.Count; i++)
            {
                Console.WriteLine(" ================================= ");
                int type = 0;
                string tempCon = oriInput[i]["Content"];
                string mutatedCon = tempCon;
                List<string> resStr = new List<string>();
                int[] allocateMap = new int[oriInput[i]["Content"].Length];
                Console.WriteLine(tempCon);

                // Ori input and response store
                res = controller.SendInputList(oriInput);
                resStr.Add(res[i]);

                // 1-bit allocate
                for (int index = 0; index < oriInput[i]["Content"].Length; index++)
                {
                    mutatedCon = tempCon;
                    mutatedCon = mutatedCon.Remove(index, 1);
                    mutatedCon = mutatedCon.Insert(index, " ");
                    inputList[i]["Content"] = mutatedCon;
                    //Console.WriteLine(inputList[i]["Content"]);

                    res = controller.SendInputList(inputList);
                    if (!resStr.Contains(res[i]))
                    {
                        resStr.Add(res[i]);
                        type = resStr.IndexOf(res[i]);
                    }

                    Console.Write(type);
                    allocateMap[index] = type;
                    inputList[i]["Content"] = tempCon;
                }
                foreach (string str in resStr)
                {
                    Console.WriteLine();
                    Console.WriteLine(str);
                }

                Console.WriteLine();
                typeMap.Add(allocateMap);
                resList.Add(resStr);
            }

            typeResponseList = resList;
            return typeMap;
        }

        public static bool IsNumeric(string value)
        {
            return Regex.IsMatch(value, @"^[+-]?\d*[.]?\d*$");
        }

        private static void FindInterface()
        {
            Console.WriteLine();
            Console.WriteLine("============ Find Interface ============");
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = TsharkPath;
            p.StartInfo.Arguments = "-D & exit";
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();

            p.StandardInput.AutoFlush = true;

            List<string> lines = new List<string>();
            while (!p.StandardOutput.EndOfStream)
            {
                string line = p.StandardOutput.ReadLine();
                if (line.Contains("\\") && line.Contains("("))
                {
                    lines.Add(line);
                }
            }

            Console.WriteLine("\n*** Interfaces: ");
            foreach (string line in lines)
            {
                Console.WriteLine(line);
            }

            p.WaitForExit();
            p.Close();

            Console.WriteLine("\n*** Please select an Interface (number):");
            string strnum = Console.ReadLine();

            int number = Convert.ToInt32(strnum);
            if (number > 0 && number < lines.Count + 1)
            {
                number--;
                InterfaceName = lines[number].Substring(lines[number].LastIndexOf("(") + 1, lines[number].LastIndexOf(")") - lines[number].LastIndexOf("(") - 1);
                Console.WriteLine("\n*** " + InterfaceName + " was selected");
            }
        }

        private static int FindServerIP(List<Dictionary<string, string>> oriInput)
        {
            currentStep = "FindServerIP";
            Console.WriteLine();
            Console.WriteLine("============ Find Server IP ============");


            controller.SendInputList(oriInput);
            string[] outs = MonitorMessage.Split('\n');
            for (int i = 0; i < outs.Length; i++) Console.WriteLine(i + ". " + outs[i]);

            Console.WriteLine("\n*** Please select a Server IP (number):");
            string strnum = Console.ReadLine();
            int number = Convert.ToInt32(strnum);

            while (number < 0 || number >= outs.Length - 1)
            {
                Console.WriteLine("Wrong Number, Please seletct a new one :");
                strnum = Console.ReadLine();
                number = Convert.ToInt32(strnum);
            }

            string ip = outs[number].Substring(outs[number].IndexOf("\"") + 1, outs[number].Substring(outs[number].IndexOf("\"") + 1).IndexOf("\"") - outs[number].IndexOf("\""));
            Console.WriteLine("\n*** " + ip + " was selected");
            ServerIP = ip;

            return 0;
        }



        /* S2D -> the message from server to Device, D2S -> the message from Device to Server
         * Return Magic Number:
         * 0 -> no S2D and D2S
         * 1 -> captured S2D but no D2S
         * 2 -> captured D2S but no S2D (almost impossible)
         * 3 -> captured D2S and S2D 
         */
        private static int MonitorNetTraffic()
        {
            string str = TsharkPath + " -i " + InterfaceName + "-T fields -e ip.src -e ip.dst -e _ws.col.Info -E separator=, -E quote=d -l -a duration:5";
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            p.StandardInput.WriteLine(str + "&exit");
            p.StandardInput.AutoFlush = true;

            //string output = p.StandardOutput.ReadToEnd();
            List<string> outs = new List<string>();
            Console.WriteLine("*** Tshark Results:");
            int index = 1;
            while (!p.StandardOutput.EndOfStream)
            {
                string line = p.StandardOutput.ReadLine();
                if (line.StartsWith("\""))
                {
                    Console.WriteLine(index + ". " + line);
                    index++;
                    outs.Add(line);
                }
            }

            p.WaitForExit();
            p.Close();

            return 0;
        }

        /* need to fix */
        public static void testStrat(System.Diagnostics.Process p)
        {
            //string str = TsharkPath + " -i " + InterfaceName + " -Y \"ip.src == " + DeviceIP + " \" -T fields -e ip.dst -e _ws.col.Info -E separator=, -E quote=d -a 5";
            //p.StartInfo.Arguments = " -i " + InterfaceName + " -T fields -e ip.dst -e _ws.col.Info -E separator=, -E quote=d >> "+ Environment.CurrentDirectory
            //               + Path.DirectorySeparatorChar + "monitor" + Path.DirectorySeparatorChar + DateTime.Now.ToString("hh-mm-ss") + ".txt 2>&1"; -e frame.time
            p.StartInfo.Arguments = " -i " + InterfaceName + " -T  fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info -E separator=, -E quote=d";
            //p.StartInfo.Arguments = " -i " + InterfaceName;
            p.Start();
            MonitorMessage = "";
            p.OutputDataReceived += new System.Diagnostics.DataReceivedEventHandler(onDataReceived);
            p.BeginOutputReadLine();
            //p.StandardInput.AutoFlush = true;
        }

        /* need to fix */
        public static void testEnd(System.Diagnostics.Process p)
        {
            CurrentMonitorMessageIndex = new List<int>();

            p.StandardInput.WriteLine("\x03");
            p.Kill();
            p.StandardInput.Close();

            //Console.WriteLine("data:");
            //Console.WriteLine(MonitorMessage);
            p.WaitForExit();
            p.Close();

            if (Program.currentStep.Equals("Detection4Randonmness") || Program.currentStep.Equals("FirstState"))
            {
                string[] outs = MonitorMessage.Trim().Split('\n');
                Dictionary<string, string> UsefulMessages = new Dictionary<string, string>();
                string time = "";

                int index = 0;
                while (!outs[index].Contains("Server Hello"))
                {
                    index++;
                    if (index >= outs.Length)
                    {
                        //Console.WriteLine(" TestEnd ERROR : no server hello");
                        return;
                        //System.Environment.Exit(0);
                    }
                }
                ServerIP = outs[index].Split('\"')[3];
                //Console.WriteLine(ServerIP);

                for (int i = 0; i < outs.Length - 1; i++)
                {
                    if (outs[i].Split('\"').Length > 5)
                    {
                        if (outs[i].Split('\"')[5].Equals(ServerIP) && outs[i].Contains("Client Hello"))
                        {
                            time = outs[i].Split(' ')[3];
                            UsefulMessages.Add(time, outs[i]);
                            //Console.WriteLine(time);
                            DateTime tsharkTime = Convert.ToDateTime(time);
                            DateTime tStartTime;

                            for (int j = 0; j < TstartTime.Count; j++)
                            {
                                tStartTime = Convert.ToDateTime(TstartTime[j]);
                                TimeSpan ts = tsharkTime.Subtract(tStartTime).Duration();
                                if (ts.Hours > 23)
                                {
                                    if (DateTime.Compare(tsharkTime, tStartTime) > 0)
                                    {
                                        CurrentMonitorMessageIndex.Add(j - 1);
                                        break;
                                    }
                                }
                                else
                                {
                                    if (DateTime.Compare(tsharkTime, tStartTime) < 0)
                                    {
                                        CurrentMonitorMessageIndex.Add(j - 1);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                //foreach (string str in TstartTime) Console.WriteLine("Start : "+str);
                //Console.WriteLine();
            }

        }

        public static void onDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                if (e.Data.Length > 10) MonitorMessage += e.Data + '\n';
            }
            else
            {
                //Console.WriteLine("No Data in Tshark");
            }
        }

        public static void ReadInterestingValue(string interestingValueFile)
        {
            if (File.Exists(DictionaryFile))
            {
                StreamReader sr = new StreamReader(DictionaryFile, Encoding.UTF8);
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    InterestingValue.Add(line.Trim('\n'));
                }
                sr.Close();
            }
        }


        /*===================================================================================================================*/

        /* Main */
        static void Main(string[] args)
        {
            //DeviceIP = "192.168.0.222";  // test only
            DeviceIP = "192.168.0.253";  // test only
            ServerIP = "";
            fuzzMode = 2;   // test only
            recordMode = false; // test only
            ConnectMode = "Socket";
            //ConnectMode = "HttpRequest";
            InputBytesMode = "Byte";
            //InputBytesMode = "String";

            /* initialize the interesting dictionary */
            TestInt = new List<string[]>();
            TestInt.Add(TestInt8);
            TestInt.Add(TestInt16);
            TestInt.Add(TestInt32);
            InterestingValue = new List<string>();

            PhysicalRestoreFile = System.Environment.CurrentDirectory + "\\in\\physical-restore.txt";

            DeviceName = "magichue";

            OriInputFile = System.Environment.CurrentDirectory + "\\in\\magichue-light-record.txt";
            RestoreInputFile = System.Environment.CurrentDirectory + "\\in\\magichue-light-restore.txt";


            DictionaryFile = System.Environment.CurrentDirectory + "\\dic\\DumbDict.txt";
            InterestingValueFile = System.Environment.CurrentDirectory + "\\dic\\RBDict.txt";
            OutFold = System.Environment.CurrentDirectory + "\\out\\";
            //RecordFold = System.Environment.CurrentDirectory + "\\record\\";
            //RecordFile = System.Environment.CurrentDirectory + "\\record\\smartplug07-03-57.txt";


            TsharkPath = "F:\\wireshark\\tshark.exe";

            ReadInterestingValue(InterestingValueFile);

            /* Input message format - List<Dictionary<string, string>>
             * Input messages were read from the txt file and IoT devices may have different communication attrs.
             * But some attrs are necessary and their name cannot be changed.
             * =========================================
             * In * HttpRequest * ConnectMode
             * They are : 1) "Content" 
             *            2) "Method"
             *            3) "URL"
             *            4) "ContentType"
             * =========================================         
             * In * Socket * ConnectMode
             * They are : 1) "IP"
             *            2) "Port"
             *            3) "Content"
             */
            List<Dictionary<string, string>> OriInput = new List<Dictionary<string, string>>();
            List<List<string>> resList = new List<List<string>>();

            OriInput = Controller.ReadInputFromFile(OriInputFile);
            RestoreInput = Controller.ReadInputFromFile(RestoreInputFile);
            PhyRestoreInput = Controller.ReadInputFromFile(PhysicalRestoreFile,"restore");

            MonitorMessageIndex = new List<int>();
            firstState = new List<List<int>>();
            firstType = new List<List<int>>();

            controller = new Controller();

            currentStep = "Main";



            //int tsharkFlag;
            //tsharkFlag = FindServerIP(OriInput);

            /* Mutation mode :      1) Dumb - 
                                    2) RB   - 
            */

            switch (fuzzMode)
            {
                case 0:
                    DumbFuzz(OriInput);
                    break;
                case 1:
                    FindInterface();
                    RBFuzz(OriInput);
                    break;
                case 2:
                    RBFuzz(OriInput);
                    break;
                default:
                    break;
            }
        }
    }
}
