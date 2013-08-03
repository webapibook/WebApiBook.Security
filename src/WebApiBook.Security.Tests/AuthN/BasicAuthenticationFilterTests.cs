using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using WebApiBook.Security.AuthN;
using WebApiBook.Security.Tests.Utils;
using Xunit;

namespace WebApiBook.Security.Tests.AuthN
{
    public class BasicAuthenticationFilterTests : BasicAuthenticationTestBase
    {
        public BasicAuthenticationFilterTests()
            : base(config => config.Filters.Add(new BasicAuthenticationFilter("myrealm", BasicAuthenticationTestBase.TestValidator)))
        {}

        [Fact]
        public async Task All_filters_add_a_challenge()
        {
            await Tester.Run(
                 withConfiguration: config =>
                 {
                     config.Filters.Add(new BasicAuthenticationFilter("myrealm1",
                         BasicAuthenticationTestBase.TestValidator));
                     config.Filters.Add(new BasicAuthenticationFilter("myrealm2",
                         BasicAuthenticationTestBase.TestValidator));
                 },
                 withRequest: () =>
                 {
                     var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                     req.Headers.Authorization = new AuthenticationHeaderValue("basic",
                         Convert.ToBase64String(
                         Encoding.UTF8.GetBytes("Alice:NotAlice")));
                     return req;
                 },
                 assertInAction: controller =>
                 {
                     Assert.False(true, "should not reach here");
                     return new HttpResponseMessage();
                 },
                 assertResponse: response =>
                 {
                     Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                     Assert.Equal(2, response.Headers.WwwAuthenticate.Count);
                 }
            );
        }

    }
}