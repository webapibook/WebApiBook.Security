using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using WebApiBook.Security.Common;
using Xunit;

namespace WebApiBook.Security.Facts
{
    public class CertPinningFacts
    {
        private const string MsItMachineAuthCa2 = "ef86b413f0fc25ac512b8be9b6ec70f6da341655";
        private const string microsoftInternetAuthority = "992ad44d7dce298de17e6f2f56a7b9caa41db93f";
        private readonly CertThumbprintSet msftThumbs = new CertThumbprintSet(
            MsItMachineAuthCa2,
            microsoftInternetAuthority);

        [Fact]
        public async Task Azure_blob_has_MSFT_cert_in_path()
        {
            var h = new WebRequestHandler();
            h.SetValidator(info =>
                !info.HasErrors &&
                new AtLeastOneThumbprintInCertChain(msftThumbs).Eval(info));
            using (var client = new HttpClient(h))
            {
                await client.GetAsync("https://webapibook.blob.core.windows.net/");
            }
        }

        private readonly CertThumbprintSet verisignCerts = new CertThumbprintSet(
            "85371ca6e550143dce2803471bde3a09e8f8770f",
            "62f3c89771da4ce01a91fc13e02b6057b4547a1d",

            "4eb6d578499b1ccf5f581ead56be3d9b6744a5e5",
            "‎5deb8f339e264c19f6686f5f8f32b54a4c46b476"
            );

        [Fact]
        public async Task Twitter_cert_pinning()
        {
            var h = new WebRequestHandler();
            h.ServerCertificateValidationCallback = (sender, certificate, chain, errors) =>
            {
                var caCerts = chain.ChainElements
                    .Cast<X509ChainElement>().Skip(1)
                    .Select(elem => elem.Certificate);

                return errors == SslPolicyErrors.None &&
                       caCerts.Any(cert => verisignCerts.Contains(cert.GetCertHashString()));
            };

            using (var client = new HttpClient(h))
            {
                await client.GetAsync("https://api.twitter.com");

                var exc = Assert.Throws<AggregateException>(() =>
                    client.GetAsync("https://api.github.com/").Result);
                Assert.IsType<HttpRequestException>(exc.InnerExceptions[0]);
            }
        }

        [Fact]
        public async Task Twitter_cert_pinning_and_revocation_checking()
        {
            ServicePointManager.CheckCertificateRevocationList = true;
            var h = new WebRequestHandler();
            h.ServerCertificateValidationCallback = (sender, certificate, chain, errors) =>
            {
                var caCerts = chain.ChainElements
                    .Cast<X509ChainElement>().Skip(1)
                    .Select(elem => elem.Certificate);

                return errors == SslPolicyErrors.None &&
                       caCerts.Any(cert => verisignCerts.Contains(cert.GetCertHashString())) &&
                       chain.ChainPolicy.RevocationMode == X509RevocationMode.Online;
            };

            using (var client = new HttpClient(h))
            {
                await client.GetAsync("https://api.twitter.com");

                var exc = Assert.Throws<AggregateException>(() =>
                    client.GetAsync("https://api.github.com/").Result);
                Assert.IsType<HttpRequestException>(exc.InnerExceptions[0]);
            }
        }

        [Fact]
        public async Task It_is_possible_to_control_revocation_checking()
        {
            var h = new WebRequestHandler();
            ServicePointManager.CheckCertificateRevocationList = true;
            h.SetValidator(info =>
                           !info.HasErrors &&
                           info.ChainPolicyUsed(X509RevocationFlag.ExcludeRoot) &&
                           info.ChainPolicyUsed(X509RevocationMode.Online) &&
                            new AtLeastOneThumbprintInCertChain(msftThumbs).Eval(info));
            using (var client = new HttpClient(h))
            {
                await client.GetAsync("https://webapibook.blob.core.windows.net/");
            }
        }

        [Fact]
        public void GitHub_doest_not_have_MSFT_cert_in_path()
        {
            var h = new WebRequestHandler();
            h.SetValidator(info =>
                !info.HasErrors &&
                new AtLeastOneThumbprintInCertChain(msftThumbs).Eval(info));
            using (var client = new HttpClient(h))
            {
                var exc = Assert.Throws<AggregateException>(() => client.GetAsync("https://api.github.com/").Result);
                Assert.IsType<HttpRequestException>(exc.InnerExceptions[0]);
            }
        }
    }
}
