using BenchmarkDotNet.Running;

namespace HkdfStandard.Benchmark
{
    class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<KeyDerivationBenchmark>();
        }
    }
}
