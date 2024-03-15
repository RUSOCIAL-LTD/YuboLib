namespace YuboLib.Models
{
    public class LoginModel
    {
        public class Error
        {
            public string code { get; set; }
            public string message { get; set; }
        }

        public class LoginResponse
        {
            public Error error { get; set; }
            public bool success { get; set; }
        }
    }
}
