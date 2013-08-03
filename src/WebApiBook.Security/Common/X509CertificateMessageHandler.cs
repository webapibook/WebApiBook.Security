using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Hosting;

namespace WebApiBook.Security.Common
{
    public class X509CertificateMessageHandler : DelegatingHandler
    {
        private readonly X509CertificateValidator _validator;
        private readonly Func<X509Certificate2, string> _issuerMapper;
        private readonly IHostPrincipalService _hostPrincipalService;

        const string X509AuthnMethod =
            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/x509";

        public X509CertificateMessageHandler(
            X509CertificateValidator validator,
            Func<X509Certificate2, string> issuerMapper,
            IHostPrincipalService hostPrincipalService
            )
        {
            _validator = validator;
            _issuerMapper = issuerMapper;
            _hostPrincipalService = hostPrincipalService;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var cert = request.GetClientCertificate();
            if (cert == null) return await base.SendAsync(request, cancellationToken);
            try
            {
                _validator.Validate(cert);
            }
            catch (SecurityTokenValidationException)
            {
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            }
            var issuer = _issuerMapper(cert);
            if (issuer == null)
            {
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            }

            var claims = ExtractClaims(cert, issuer);
            var identity = new ClaimsIdentity(new ClaimsIdentity(claims, X509AuthnMethod));
            AddIdentityToCurrentPrincipal(identity, request);

            return await base.SendAsync(request, cancellationToken);
        }

        private static IEnumerable<Claim> ExtractClaims(X509Certificate2 cert, string issuer)
        {
            var claims = new Collection<Claim>
            {
                new Claim(ClaimTypes.Thumbprint,Convert.ToBase64String(cert.GetCertHash()),
                    ClaimValueTypes.Base64Binary, issuer),
                new Claim(ClaimTypes.X500DistinguishedName, cert.SubjectName.Name, 
                    ClaimValueTypes.String, issuer),
                new Claim(ClaimTypes.SerialNumber, cert.SerialNumber, 
                    ClaimValueTypes.String, issuer),
                new Claim(ClaimTypes.AuthenticationMethod, X509AuthnMethod,
                    ClaimValueTypes.String, issuer)
            };
            var email = cert.GetNameInfo(X509NameType.EmailName, false);
            if (email != null)
            {
                claims.Add(new Claim(ClaimTypes.Email, email, ClaimValueTypes.String, issuer));
            }
            return claims;
        }

        private void AddIdentityToCurrentPrincipal(ClaimsIdentity identity, HttpRequestMessage request)
        {
            var principal = _hostPrincipalService.GetCurrentPrincipal(request) as ClaimsPrincipal;
            if (principal == null)
            {
                principal = new ClaimsPrincipal(identity);
                _hostPrincipalService.SetCurrentPrincipal(principal, request);
            }
            else
            {
                principal.AddIdentity(identity);
            }
        }
    }
}