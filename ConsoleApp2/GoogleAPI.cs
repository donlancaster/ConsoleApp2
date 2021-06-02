using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Drive.v3;
using Google.Apis.Services;
using Google.Apis.Util.Store;

namespace ConsoleApp2
{
    class GoogleAPI
    {

        private static string[] Scopes = { DriveService.Scope.Drive };
        private static string ApplicationName = "ConsoleApp2";
        private static string FolderId = "1Pglota0Zz5ghdUXzTY-tzGOAmTMZdGvb"; // указать
        
        private static string filePath = AppDomain.CurrentDomain.BaseDirectory;
       

        public static void Process(string fileName, string contentType)
        {
            UserCredential credential = GetUserCredential();
            DriveService service = GetDriveService(credential);

           /* IList<Google.Apis.Drive.v3.Data.File> files = service.Files.List().Execute().Files;
            foreach(var file in files)
            {
                Console.WriteLine("File Title: {0}, id: {1}", file.Name, file.Id);
            }*/
            Console.WriteLine("uploading files");
            UploadFileToDrive(service, fileName, filePath+fileName,contentType);
            
          

        }

        private static UserCredential GetUserCredential()
        {
            using (var stream = new FileStream("client_secret.json", FileMode.Open, FileAccess.Read))
            {
                string creadPath = Environment.GetFolderPath(Environment.SpecialFolder.Personal);
                creadPath = Path.Combine(creadPath, "driveApiCredentials", "drive-credentials.json");
                return GoogleWebAuthorizationBroker.AuthorizeAsync(
                    GoogleClientSecrets.Load(stream).Secrets,
                    Scopes,
                    "User",
                    CancellationToken.None,
                    new FileDataStore(creadPath, true)).Result;
            }
        }

        private static DriveService GetDriveService(UserCredential credential)
        {
            return new DriveService(
                new BaseClientService.Initializer
                {
                    HttpClientInitializer = credential,
                    ApplicationName = ApplicationName
                });
        }

        private static string UploadFileToDrive(DriveService service, string fileName, string filePath, string contentType)
        {
            var fileMetadata = new Google.Apis.Drive.v3.Data.File();
            fileMetadata.Name = fileName;
            fileMetadata.Parents = new List<string> { FolderId };
            FilesResource.CreateMediaUpload request;
            using (var stream = new FileStream(filePath, FileMode.Open))
            {
                request = service.Files.Create(fileMetadata, stream, contentType);
                request.Upload();
                //Thread.Sleep(100);
            }
            var file = request.ResponseBody;
            Console.WriteLine(file.Id);
            return file.Id;
        }


    }
}
