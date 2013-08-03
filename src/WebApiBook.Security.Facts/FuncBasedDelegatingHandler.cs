using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace WebApiBook.Security.Facts
{
    public class FuncBasedDelegatingHandler : DelegatingHandler
    {
        private readonly Func<HttpRequestMessage, Func<HttpRequestMessage, Task<HttpResponseMessage>>, Task<HttpResponseMessage>> _f;

        public FuncBasedDelegatingHandler(Func<HttpRequestMessage, Func<HttpRequestMessage, Task<HttpResponseMessage>>, Task<HttpResponseMessage>> f)
        {
            _f = f;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return _f(request, req => base.SendAsync(req, cancellationToken));
        }
    }
}