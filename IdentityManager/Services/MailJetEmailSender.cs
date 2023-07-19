using Mailjet.Client;
using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Identity.UI.Services;
using Newtonsoft.Json.Linq;

namespace IdentityManager.Services
{
    public class MailJetEmailSender : IEmailSender
    {
        private readonly IConfiguration configuration;
        private MailJetOptions _mailJetOptions;

        public MailJetEmailSender(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            _mailJetOptions = configuration.GetSection("MailJet").Get<MailJetOptions>();


            MailjetClient client = new MailjetClient(_mailJetOptions.ApiKey, _mailJetOptions.SecretKey);

            MailjetRequest request = new MailjetRequest
            {
                Resource = SendV31.Resource,
            }
             .Property(Send.Messages, new JArray {
                                                     new JObject {
                                                      {
                                                       "From", new JObject {{"Email", "jeevan_desai@proton.me"}, {"Name", "Jeevan"} }
                                                      },
                                                      {"To", new JArray {new JObject { { "Email",email} } } },
                                                      {    "Subject",        subject      },
                                                         {        "HTMLPart",       htmlMessage       }      }
                        });
            await client.PostAsync(request);
        }
    }

}
