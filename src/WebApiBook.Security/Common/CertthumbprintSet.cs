using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebApiBook.Security.Common
{
    public class CertThumbprintSet : HashSet<string>
    {
        public CertThumbprintSet(params string[] thumbs)
            : base(thumbs, StringComparer.OrdinalIgnoreCase)
        { }
    }
}
