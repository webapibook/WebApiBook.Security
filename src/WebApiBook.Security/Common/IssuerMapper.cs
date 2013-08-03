using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace WebApiBook.Security.Common
{
    public static class IssuerMapper
    {
        public static Func<X509Certificate2, string> FromIssuerDn()
        {
            return cert => cert.IssuerName.Name;
        }

        public static Func<X509Certificate2, string> FromIssuerRegistry(IssuerNameRegistry registry)
        {
            return cert =>
            {
                var chain = new X509Chain
                {
                    ChainPolicy =
                    {
                        RevocationMode = X509RevocationMode.NoCheck
                    }
                };
                chain.Build(cert);
                var elems = chain.ChainElements;
                return registry.GetIssuerName(
                    new X509SecurityToken(
                        elems.Count == 1 ? elems[0].Certificate : elems[1].Certificate));
            };
        }
    }
}