using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Hosting;
using WebApiBook.Security.Common;

namespace WebApiBook.Security.AuthN
{
    public class BasicAuthenticationDelegatingHandler : DelegatingHandler
    {
        private readonly IHostPrincipalService _principalService;
        private readonly Func<string, string, Task<ClaimsPrincipal>> _validator;
        private readonly string _realm;

        public BasicAuthenticationDelegatingHandler(IHostPrincipalService principalService, string realm, Func<string, string, Task<ClaimsPrincipal>> validator)
        {
            _principalService = principalService;
            _validator = validator;
            _realm = "realm=" + realm;
        }

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            HttpResponseMessage res;
            if (!request.HasAuthorizationHeaderWithBasicScheme())
            {
                res = await base.SendAsync(request, cancellationToken);
            }
            else
            {
                var principal = await request.TryGetPrincipalFromBasicCredentialsUsing(_validator);
                if (principal != null)
                {
                    _principalService.SetCurrentPrincipal(principal, request);
                    res = await base.SendAsync(request, cancellationToken);
                }
                else
                {
                    res = request.CreateResponse(HttpStatusCode.Unauthorized);
                }
            }

            if (res.StatusCode == HttpStatusCode.Unauthorized)
            {
                res.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Basic", _realm));
            }
            return res;
        }
    }
}
