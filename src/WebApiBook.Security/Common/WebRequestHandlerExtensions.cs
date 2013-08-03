using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace WebApiBook.Security.Common
{
    public static class WebRequestHandlerExtensions
    {
        public static void SetValidator(
            this WebRequestHandler handler,
            Func<CertValidateInfo, bool> validator)
        {
            var previousHandler = handler.ServerCertificateValidationCallback;

            handler.ServerCertificateValidationCallback =
                (sender, certificate, chain, errors) =>
                    (previousHandler == null || previousHandler(sender, certificate, chain, errors)) &&
                    validator(new CertValidateInfo(certificate, chain, errors));
        }
    }
}
