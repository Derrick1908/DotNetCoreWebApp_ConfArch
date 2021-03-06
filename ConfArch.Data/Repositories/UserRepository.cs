using ConfArch.Data.Models;
using System.Linq;
using System.Collections.Generic;
using System.Text;

namespace ConfArch.Data.Repositories
{
    public class UserRepository : IUserRepository
    {
        private List<User> users = new List<User>
        {
            new User{
                Id = 3522, Name = "roland", Password = "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",  //The Pasword currently set is "secret" and is stored in Cryptographic Hash Form
                FavoriteColor = "blue", Role = "Admin", GoogleId = "117002938807255470278" } 
        };

        public User GetByUsernameAndPassword(string username, string password)
        {
            var user = users.SingleOrDefault(u => u.Name == username && u.Password == password.Sha256());
            return user;
        }

        public User GetByGoogleId(string googleId)
        {
            var user = users.SingleOrDefault(u => u.GoogleId == googleId);
            return user;
        }
    }
}
