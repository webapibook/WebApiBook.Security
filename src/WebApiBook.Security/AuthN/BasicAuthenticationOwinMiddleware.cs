using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using WebApiBook.Security.Common;

namespace WebApiBook.Security.AuthN
{
    class BasicAuthnMiddleware : AuthenticationMiddleware<BasicAuthenticationOptions>
    {
        public BasicAuthnMiddleware(OwinMiddleware next, BasicAuthenticationOptions options)
            : base(next, options)
        {
        }

        protected override AuthenticationHandler<BasicAuthenticationOptions> CreateHandler()
        {
            return new BasicAuthenticationHandler();
        }
    }

    public class BasicAuthenticationOptions : AuthenticationOptions
    {
        public Func<string, string, Task<AuthenticationTicket>> ValidateCredentials { get; set; }

        public string Realm { get; set; }

        public BasicAuthenticationOptions()
            : base("Basic")
        { }
    }

    public static class BasicAuthnMiddlewareExtensions
    {
        public static IAppBuilder UseBasicAuthentication(this IAppBuilder app, BasicAuthenticationOptions options)
        {
            return app.Use(typeof(BasicAuthnMiddleware), options);
        }
    }

    class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        private bool _terminateRequest = false;

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var authzValue = Request.Headers.Get("Authorization");
            if (string.IsNullOrEmpty(authzValue) || !authzValue.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            var token = authzValue.Substring("Basic ".Length).Trim();

            var princ = await token.TryGetPrincipalFromBasicCredentialsUsing(Options.ValidateCredentials);
            if (princ == null) _terminateRequest = true;
            return princ;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                Response.Headers.Append("WWW-Authenticate", "Basic realm=" + Options.Realm);
            }
            return Task.FromResult<object>(null);
        }

        public override Task<bool> InvokeAsync()
        {
            if (_terminateRequest)
            {
                Response.StatusCode = 401;
            }
            return Task.FromResult(_terminateRequest);
        }
    }
}
