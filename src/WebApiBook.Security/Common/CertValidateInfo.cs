using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace WebApiBook.Security.Common
{
    public class CertValidateInfo
    {
        public X509Certificate Certificate { get; private set; }
        public X509Chain Chain { get; private set; }
        public SslPolicyErrors PolicyErrors { get; private set; }

        public CertValidateInfo(X509Certificate cert, X509Chain chain, SslPolicyErrors policyErrors)
        {
            Certificate = cert;
            Chain = chain;
            PolicyErrors = policyErrors;
        }

        public bool HasErrors
        {
            get
            {
                return PolicyErrors != SslPolicyErrors.None;
            }
        }
        public bool ChainPolicyUsed(X509RevocationFlag flag)
        {
            return Chain.ChainPolicy.RevocationFlag == flag;
        }
        public bool ChainPolicyUsed(X509RevocationMode mode)
        {
            return Chain.ChainPolicy.RevocationMode == mode;
        }
    }
}