using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;
using System.Web.Http.Results;
using WebApiBook.Security.Common;

namespace WebApiBook.Security.AuthN
{

    public class BasicAuthenticationFilter : IAuthenticationFilter
    {
        private readonly Func<string, string, Task<IPrincipal>> _validate;
        private readonly string _realm;
        public bool AllowMultiple { get { return false; } }

        public BasicAuthenticationFilter(string realm, Func<string, string, Task<IPrincipal>> validate)
        {
            _validate = validate;
            _realm = "realm=" + realm;
        }

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var req = context.Request;
            if (HasAuthorizationHeaderWithBasicScheme(req))
            {
                var principal = await TryValidateCredentialsAndCreatePrincipal(req.Headers.Authorization.Parameter);
                if (principal != null)
                {
                    context.Principal = principal;
                }
                else
                {
                    // challenges will be added by the ChallengeAsync
                    context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0],
                        context.Request);
                }
            }
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ActionResultDelegate(context.Result, async (ct, next) =>
            {
                var res = await next.ExecuteAsync(ct);
                if (res.StatusCode == HttpStatusCode.Unauthorized)
                {
                    res.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Basic", _realm));
                }
                return res;
            });
            return Task.FromResult<object>(null);
        }

        private bool HasAuthorizationHeaderWithBasicScheme(HttpRequestMessage req)
        {
            return req.Headers.Authorization != null
                   && req.Headers.Authorization.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase);
        }

        private async Task<IPrincipal> TryValidateCredentialsAndCreatePrincipal(string creds)
        {
            string pair;
            try
            {
                pair = Encoding.UTF8.GetString(Convert.FromBase64String(creds));
            }
            catch (FormatException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
            var ix = pair.IndexOf(':');
            if (ix == -1) return null;
            var username = pair.Substring(0, ix);
            var pw = pair.Substring(ix + 1);
            return await _validate(username, pw);
        }
    }

}
