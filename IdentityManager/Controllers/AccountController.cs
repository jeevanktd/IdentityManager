using IdentityManager.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityManager.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IEmailSender emailSender;

        public AccountController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager, IEmailSender emailSender)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.emailSender = emailSender;
        }


        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Register(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            RegisterViewModel registerViewModel = new RegisterViewModel();
            return View(registerViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = registerViewModel.Email,
                    Email = registerViewModel.Email,
                    Name = registerViewModel.Name
                };

                var result = await userManager.CreateAsync(user,
                    registerViewModel.Password);

                if (result.Succeeded)
                {
                    var code = await userManager.GenerateEmailConfirmationTokenAsync(user);


                    var callbackurl = Url.Action("ConfirmEmail", "Account",
                                            new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme
                                            );

                    await emailSender.SendEmailAsync(registerViewModel.Email,
                        "Confirm Your Email - Identity Manager Application - JeevanDesai",
                        "Please confirm your account by clicking on link - <a href=\"" + callbackurl + "\">link</a>");



                    await signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl);

                }

                AddErrors(result);

            }
            return View(registerViewModel);
        }

        // Thhis will set email confirmation flag to 1 in AspNetUSers table
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(code))
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    var result = await userManager.ConfirmEmailAsync(user, code);
                    if (result.Succeeded)
                    {
                        return View("ConfirmEmail");
                    }
                }
            }
            return View("Error");
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }


        [HttpGet]
        public IActionResult Login(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var result = await signInManager.PasswordSignInAsync(
                    loginViewModel.Email, loginViewModel.Password,
                    isPersistent : loginViewModel.RememberMe,
                    lockoutOnFailure:true);

                if (result.Succeeded)
                {
                    return LocalRedirect(returnurl); // Open Redirect attack, check for local URL
                }
                else if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError("", "Invalid Login attempt");
                    return View(loginViewModel);
                }
            }
            return View(loginViewModel);
        }


        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel forgotPasswordViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByEmailAsync(forgotPasswordViewModel.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }
                var code = await userManager.GeneratePasswordResetTokenAsync(user);

                var callbackurl = Url.Action("ResetPassword", "Account",
                    new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme
                    );

                await emailSender.SendEmailAsync(forgotPasswordViewModel.Email,
                    "Reset Password - Identity Manager Application - JeevanDesai",
                    "Please reset your password by clicking on link - <a href=\"" + callbackurl + "\">link</a>");

                return RedirectToAction("ForgotPasswordConfirmation");
            }

            return View(forgotPasswordViewModel);
        }


        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }




        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel resetPasswordViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByEmailAsync(resetPasswordViewModel.Email);
                if (user == null)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }

                var result =  await userManager.ResetPasswordAsync(user, resetPasswordViewModel.Code,
                    resetPasswordViewModel.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }


                AddErrors(result);
            }

            return View(resetPasswordViewModel);
        }


        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        // provider = passed in button click, returnurl 
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // request a redirect to the external login provider

            var redirectUrl = Url.Action("ExternalLoginCallback", "Account",
                new { ReturnUrl = returnUrl });

            var properties = signInManager.ConfigureExternalAuthenticationProperties(provider,
                redirectUrl);

            var res= Challenge(properties, provider); // please verify this identity
            return res;
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if (remoteError != null)
            {
                ModelState.AddModelError("", $"Error from external provider - {remoteError}");
                return View(nameof(Login));
            }

            var info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider, i the user already has a login

            var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider,
                info.ProviderKey, isPersistent: false);
            if(result.Succeeded)
            {
                //update any authentication tokens

                await signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnUrl);
            }
            else
            {
                // if the user does not have account, then we will ask the user to create an account

                ViewData["ReturnUrl"] = returnUrl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;

                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var name = info.Principal.FindFirstValue(ClaimTypes.Name);
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel
                {
                    Email = email,
                    Name = name
                }); ;

            }
        }

        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel externalLoginConfirmationViewModel, string returnurl = null)
        {
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                // get the info about the user from external login provider
                var info = await signInManager.GetExternalLoginInfoAsync();
                if(info == null)
                {
                    return View("Error");
                }

                var user = new ApplicationUser
                {
                    UserName = externalLoginConfirmationViewModel.Email,
                    Email = externalLoginConfirmationViewModel.Email,
                    Name = externalLoginConfirmationViewModel.Name,
                };
                var result = await userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await userManager.AddLoginAsync(user, info);
                    if(result.Succeeded)
                    {
                        await signInManager.SignInAsync(user, isPersistent: false);
                        await signInManager.UpdateExternalAuthenticationTokensAsync(info);
                        return LocalRedirect(returnurl);
                    }
                }
                AddErrors(result);
            }
            ViewData["ReturnUrl"] = returnurl;
            return View(externalLoginConfirmationViewModel);
        }


        private void AddErrors(IdentityResult result)
        {
            foreach(var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

    }
}
