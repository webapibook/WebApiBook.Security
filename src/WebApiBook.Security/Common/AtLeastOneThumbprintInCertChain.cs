using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace WebApiBook.Security.Common
{
    public class AtLeastOneThumbprintInCertChain
    {
        public AtLeastOneThumbprintInCertChain(CertThumbprintSet hashes)
        {
            _hashes = hashes;
        }

        private readonly CertThumbprintSet _hashes;
        public bool Eval(CertValidateInfo info)
        {
            var caCerts = info.Chain.ChainElements
                .Cast<X509ChainElement>().Skip(1)
                .Select(elem => elem.Certificate);
            return caCerts.Any(cert => _hashes.Contains(cert.GetCertHashString()));
        }
    }
}
