using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Claims;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace WebApiBook.Security.AuthN
{
    class JwtAuthnMiddleware : AuthenticationMiddleware<JwtAuthenticationOptions>
    {
        public JwtAuthnMiddleware(OwinMiddleware next, JwtAuthenticationOptions options)
            : base(next, options)
        {
        }

        protected override AuthenticationHandler<JwtAuthenticationOptions> CreateHandler()
        {
            return new JwtAuthenticationHandler();
        }
    }

    public class JwtAuthenticationOptions : AuthenticationOptions
    {
        public string Realm { get; set; }

        public JwtAuthenticationOptions()
            : base("Bearer")
        {
            SecurityTokens = new Collection<SecurityToken>();
            ValidIssuers = new Collection<string>();
        }

        public string Audience { get; set; }
        public string NameClaimType { get; set; }

        public ICollection<SecurityToken> SecurityTokens { get; private set; }
        public ICollection<string> ValidIssuers { get; private set; }


        public Task<AuthenticationTicket> TryValidateToken(string tokenString, IOwinRequest request)
        {
            var validationParameters = new TokenValidationParameters()
            {
                AllowedAudience = Audience ?? DefaultAudienceFor(request),
                SigningTokens = SecurityTokens,
                ValidIssuers = ValidIssuers,
                AudienceUriMode = AudienceUriMode.Always
            };

            var tokenHandler = new JwtSecurityTokenHandler
            {
                NameClaimType = NameClaimType ?? ClaimTypes.Name,
                RequireSignedTokens = true
            };

            try
            {
                return Task.FromResult(new AuthenticationTicket(
                    tokenHandler.ValidateToken(tokenString, validationParameters).Identities.First(),
                    new AuthenticationProperties()));
            }
            catch (FormatException)
            {
                return Task.FromResult<AuthenticationTicket>(null);
            }
            catch (SecurityTokenValidationException e)
            {
                return Task.FromResult<AuthenticationTicket>(null);
            }
            catch (InvalidOperationException)
            {
                return Task.FromResult<AuthenticationTicket>(null);
            }
        }

        private static string DefaultAudienceFor(IOwinRequest request)
        {
            return "http://"+request.Host;
        }

        public JwtAuthenticationOptions WithIssuer(string issuer)
        {
            ValidIssuers.Add(issuer);
            return this;
        }

        public JwtAuthenticationOptions WithKey(string key)
        {
            SecurityTokens.Add(new BinarySecretSecurityToken(Convert.FromBase64String(key)));
            return this;
        }
    }

    public static class JwtAuthnMiddlewareExtensions
    {
        public static IAppBuilder UseJwtAuthentication(this IAppBuilder app, JwtAuthenticationOptions options)
        {
            return app.Use(typeof(JwtAuthnMiddleware), options);
        }
    }

    class JwtAuthenticationHandler : AuthenticationHandler<JwtAuthenticationOptions>
    {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var authzValue = Request.Headers.Get("Authorization");
            if (string.IsNullOrEmpty(authzValue) || !authzValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            var tokenString = authzValue.Substring("Bearer ".Length).Trim();

            return await Options.TryValidateToken(tokenString, Request);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                Response.Headers.Append("WWW-Authenticate", "Bearer realm=" + Options.Realm);
            }
            return Task.FromResult<object>(null);
        }
    }
}
