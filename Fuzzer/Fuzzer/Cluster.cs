using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Aglomera;
using Aglomera.Linkage;
using Aglomera.Evaluation;
using Aglomera.D3;
using System.Diagnostics;

namespace Fuzzer
{
    class Cluster
    {
        public class DataPoint : IEquatable<DataPoint>, IDissimilarityMetric<DataPoint>, IComparable<DataPoint>
        {
            #region Constructors

            public DataPoint(string id, double[] value)
            {
                this.ID = id;
                this.Value = value;
            }

            public DataPoint()
            {
            }

            #endregion

            #region Properties & Indexers

            public string ID { get; }

            public double[] Value { get; }

            #endregion

            #region Public Methods

            public override bool Equals(object obj) => obj is DataPoint && this.Equals((DataPoint)obj);

            public override int GetHashCode() => this.ID.GetHashCode();

            public override string ToString() => this.ID;

            #endregion

            #region Public Methods

            public static DataPoint GetCentroid(Cluster<DataPoint> cluster)
            {
                if (cluster.Count == 1) return cluster.First();

                // gets sum for all variables
                var id = new StringBuilder();
                var sums = new double[cluster.First().Value.Length];
                foreach (var dataPoint in cluster)
                {
                    id.Append(dataPoint.ID);
                    for (var i = 0; i < sums.Length; i++)
                        sums[i] += dataPoint.Value[i];
                }

                // gets average of all variables (centroid)
                for (var i = 0; i < sums.Length; i++)
                    sums[i] /= cluster.Count;

                return new DataPoint(id.ToString(), sums);
            }

            public static DataPoint GetMedoid(Cluster<DataPoint> cluster) => cluster.GetMedoid(new DataPoint());

            public static bool operator ==(DataPoint left, DataPoint right) => left.Equals(right);

            public static bool operator !=(DataPoint left, DataPoint right) => !left.Equals(right);

            public double DistanceTo(DataPoint other)
            {
                var sum2 = 0d;
                var length = Math.Min(this.Value.Length, other.Value.Length);
                for (var idx1 = 0; idx1 < length; ++idx1)
                {
                    var delta = this.Value[idx1] - other.Value[idx1];
                    sum2 += delta * delta;
                }

                return Math.Sqrt(sum2);
            }

            public int CompareTo(DataPoint other) => string.Compare(this.ID, other.ID, StringComparison.Ordinal);

            public double Calculate(DataPoint instance1, DataPoint instance2) => instance1.DistanceTo(instance2);

            public bool Equals(DataPoint other) => string.Equals(this.ID, other.ID);

            #endregion
        }

        public class PerformanceMeasure
        {
            #region Fields

            private readonly Stopwatch _timer = new Stopwatch();
            private long _memoryStart;

            #endregion

            #region Constructors

            public PerformanceMeasure()
            {
                this.TimeElapsed = new TimeSpan();
            }

            #endregion

            #region Properties & Indexers

            public long MemoryUsage { get; protected set; }

            public TimeSpan TimeElapsed { get; protected set; }

            #endregion

            #region Public methods

            public virtual void Start()
            {
                //starts measures (time and memory)
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                this._memoryStart = Process.GetCurrentProcess().PrivateMemorySize64;
                this._timer.Start();
            }

            public virtual void Stop()
            {
                //stops timers and measures
                this._timer.Stop();
                var memoryEnd = Process.GetCurrentProcess().PrivateMemorySize64;

                this.TimeElapsed = this._timer.Elapsed;
                this.MemoryUsage += memoryEnd - this._memoryStart;
            }

            public void Reset()
            {
                // "zero"s all measures
                this._timer.Stop();
                this.MemoryUsage = 0;
                this.TimeElapsed = new TimeSpan();
            }

            public override string ToString()
            {
                return $"time elapsed: {this.TimeElapsed}, memory spent: {BytesToString(this.MemoryUsage)}";
            }

            private static string BytesToString(long byteCount)
            {
                string[] suf = { "B", "KB", "MB", "GB", "TB", "PB", "EB" }; //Longs run out around EB
                if (byteCount == 0)
                    return "0" + suf[0];
                var bytes = Math.Abs(byteCount);
                var place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
                var num = Math.Round(bytes / Math.Pow(1024, place), 1);
                return Math.Sign(byteCount) * num + suf[place];
            }

            #endregion
        }


        public static void PrintClusters(ISet<DataPoint> instances, ILinkageCriterion<DataPoint> linkage, string name)
        {
            var perfMeasure = new PerformanceMeasure();
            perfMeasure.Start();
            var clusteringAlg = new AgglomerativeClusteringAlgorithm<DataPoint>(linkage);
            var clustering = clusteringAlg.GetClustering(instances);
            perfMeasure.Stop();

            Console.WriteLine("_____________________________________________");
            Console.WriteLine(name);
            Console.WriteLine(perfMeasure);
            foreach (var clusterSet in clustering)
            {
                Console.WriteLine($"Clusters at distance: {clusterSet.Dissimilarity:0.00} ({clusterSet.Count})");
                foreach (var cluster in clusterSet)
                    Console.WriteLine($" - {cluster}");
            }

        }

    }
}
