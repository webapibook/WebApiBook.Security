using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Testing;
using Owin;

namespace WebApiBook.Security.Tests.AuthN
{
    public static class OwinTester
    {
        public async static Task Run(
            Action<IAppBuilder> useConfiguration,
            Func<HttpRequestMessage> useRequest,
            Action<IOwinContext> assertRequest,
            Action<HttpResponseMessage> assertResponse)
        {
            var server = TestServer.Create(app =>
            {
                useConfiguration(app);
                app.Use((ctx, next) =>
                {
                    assertRequest(ctx);
                    return Task.FromResult<object>(null);
                });
            });
            var request = useRequest();
            request.Headers.Host = request.RequestUri.Host;
            var response = await server.HttpClient.SendAsync(request);
            assertResponse(response);
        }
    }
}