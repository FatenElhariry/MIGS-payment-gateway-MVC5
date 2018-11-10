
using MigsPayments.Helpers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace MigsPayments.Controllers
{
    public class PaymentSHA256Controller : Controller
    {
        // GET: Payment
        public ActionResult Index()
        {

            var PaymentStatus = "none";
            SortedList<String, String> _responseFields = new SortedList<String, String>(new VPCStringComparer());

            try
            {
                string hashSecret = ConfigurationManager.AppSettings["MigsSecureHashSecret"];
                var secureHash = Request.QueryString["vpc_SecureHash"];
                var txnResponseCode = Request.QueryString["vpc_TxnResponseCode"];
                if (!string.IsNullOrEmpty(secureHash))
                {
                    if (!string.IsNullOrEmpty(hashSecret))
                    {
                        var rawHashData = hashSecret + string.Join("", Request.QueryString.AllKeys.Where(k => k != "vpc_SecureHash").Select(k => Request.QueryString[k]));
                        Request.QueryString.AllKeys.All(c =>
                        {
                            _responseFields.Add(c, Request.QueryString[c]);
                            return true;
                        });
                        var signature = PaymentHelperMethods.CreateSHA256Signature(_responseFields);
                        if (signature != secureHash || txnResponseCode != "0")
                        {
                            PaymentStatus = "invalid";
                            //return View("Error", new ApplicationException("Invalid request."));
                        }
                        else
                        {
                            PaymentStatus = "approved";
                        }
                    }
                }

                ViewBag.PaymentStatus = PaymentStatus;

                var vpcResponse = new PaymentResponse(Request);
                return View(vpcResponse);

            }
            catch (Exception ex)
            {

                var message = "Exception encountered. " + ex.Message;
                return View("Error", ex);

            }

        }




        // POST: Payment/InitiatePayment

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult InitiatePayment([Bind(Include = "vpc_Amount, vpc_MerchTxnRef, vpc_OrderInfo, vpc_ReturnURL")] string vpc_Amount, string vpc_MerchTxnRef, string vpc_OrderInfo, string vpc_ReturnURL)
        {
            SortedList<String, String> _requestFields = new SortedList<String, String>(new VPCStringComparer());
            try
            {

                //region parameters
                var VPC_URL = "https://migs.mastercard.com.au/vpcpay";
                int amount = int.Parse(vpc_Amount) * 100;
                var paymentRequest = new PaymentRequest
                {
                    Amount = amount.ToString(),
                    MerchTxnRef = vpc_MerchTxnRef,
                    OrderInfo = vpc_OrderInfo,
                    ReturnUrl = vpc_ReturnURL
                };

                string hashSecret = ConfigurationManager.AppSettings["MigsSecureHashSecret"];
                //endregion


                //region redirect to payment gateway
                var transactionData = paymentRequest.GetParameters().OrderBy(t => t.Key, new VPCStringComparer()).ToList();
                transactionData.All(c =>
                {
                    _requestFields.Add(c.Key, c.Value);
                    return true;
                });
                // Add custom data, transactionData.Add(new KeyValuePair<string, string>("Title", title));
                // return Content(string.Join("&", transactionData.Select(item => HttpUtility.UrlEncode(item.Key) + "=" + HttpUtility.UrlEncode(item.Value))));
                var redirectUrl = VPC_URL + "?" + string.Join("&", transactionData.Select(item => HttpUtility.UrlEncode(item.Key) + "=" + HttpUtility.UrlEncode(item.Value)));
                if (!string.IsNullOrEmpty(hashSecret))
                {
                    string re = string.Join("&", transactionData.Select(item => HttpUtility.UrlEncode(item.Key) + "=" + HttpUtility.UrlEncode(item.Value)));
                    redirectUrl += "&vpc_SecureHash=" +
                        PaymentHelperMethods.CreateSHA256Signature(_requestFields);
                    redirectUrl += "&vpc_SecureHashType=SHA256";
                }
                return Redirect(redirectUrl);
                //endregion

            }
            catch (Exception ex)
            {
                var message = "Exception encountered. " + ex.Message;
                return View("Error", ex);
            }
        }
    }
}