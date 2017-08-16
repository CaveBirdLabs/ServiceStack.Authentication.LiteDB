using System;
using System.Collections.Generic;
using System.Linq;
using LiteDB;
using ServiceStack.Auth;

namespace ServiceStack.Authentication.LiteDB
{
	public class LiteDBAuthRepository : IUserAuthRepository, IClearable, IManageApiKeys
	{
		readonly LiteDatabase _liteDatabase;

		public LiteDBAuthRepository(LiteDatabase liteDatabase, bool createMissingCollections)
		{
			_liteDatabase = liteDatabase;

			if (createMissingCollections)
				CreateMissingCollections();

			if (!CollectionsExists())
				throw new InvalidOperationException("One of the collections needed by LiteDBAuthRepository is missing." +
				                                    "You can call LiteDBAuthRepository constructor with the parameter CreateMissingCollections set to 'true'  " +
				                                    "to create the needed collections.");
		}

		static string UserAuthCol => typeof(UserAuth).Name;
		static string UserOAuthProviderCol => typeof(UserAuthDetails).Name;
		static string ApiKeysCol => typeof(ApiKey).Name;

		public void Clear()
		{
			DropAndReCreateCollections();
		}

		public IUserAuth CreateUserAuth(IUserAuth newUser, string password)
		{
			newUser.ValidateNewUser(password);

			AssertNoExistingUser(_liteDatabase, newUser);

			var saltedHash = HostContext.Resolve<IHashProvider>();
			string salt;
			string hash;
			saltedHash.GetHashAndSaltString(password, out hash, out salt);
			var digestHelper = new DigestAuthFunctions();
			newUser.DigestHa1Hash = digestHelper.CreateHa1(newUser.UserName, DigestAuthProvider.Realm, password);
			newUser.PasswordHash = hash;
			newUser.Salt = salt;
			newUser.CreatedDate = DateTime.UtcNow;
			newUser.ModifiedDate = newUser.CreatedDate;

			SaveUser(newUser);
			return newUser;
		}

		public IUserAuth UpdateUserAuth(IUserAuth existingUser, IUserAuth newUser, string password)
		{
			newUser.ValidateNewUser(password);

			AssertNoExistingUser(_liteDatabase, newUser, existingUser);

			var hash = existingUser.PasswordHash;
			var salt = existingUser.Salt;
			if (password != null)
			{
				var saltedHash = HostContext.Resolve<IHashProvider>();
				saltedHash.GetHashAndSaltString(password, out hash, out salt);
			}
			// If either one changes the digest hash has to be recalculated
			var digestHash = existingUser.DigestHa1Hash;
			if (password != null || existingUser.UserName != newUser.UserName)
			{
				var digestHelper = new DigestAuthFunctions();
				digestHash = digestHelper.CreateHa1(newUser.UserName, DigestAuthProvider.Realm, password);
			}
			newUser.Id = existingUser.Id;
			newUser.PasswordHash = hash;
			newUser.Salt = salt;
			newUser.DigestHa1Hash = digestHash;
			newUser.CreatedDate = existingUser.CreatedDate;
			newUser.ModifiedDate = DateTime.UtcNow;
			SaveUser(newUser);

			return newUser;
		}

		public IUserAuth UpdateUserAuth(IUserAuth existingUser, IUserAuth newUser)
		{
			newUser.ValidateNewUser();

			AssertNoExistingUser(_liteDatabase, newUser);

			newUser.Id = existingUser.Id;
			newUser.PasswordHash = existingUser.PasswordHash;
			newUser.Salt = existingUser.Salt;
			newUser.DigestHa1Hash = existingUser.DigestHa1Hash;
			newUser.CreatedDate = existingUser.CreatedDate;
			newUser.ModifiedDate = DateTime.UtcNow;
			SaveUser(newUser);

			return newUser;
		}

		public IUserAuth GetUserAuthByUserName(string userNameOrEmail)
		{
			return GetUserAuthByUserName(_liteDatabase, userNameOrEmail);
		}

		public bool TryAuthenticate(string userName, string password, out IUserAuth userAuth)
		{
			userAuth = GetUserAuthByUserName(userName);
			if (userAuth == null)
				return false;

			var saltedHash = HostContext.Resolve<IHashProvider>();
			if (saltedHash.VerifyHashString(password, userAuth.PasswordHash, userAuth.Salt))
			{
				this.RecordSuccessfulLogin(userAuth);

				return true;
			}

			this.RecordInvalidLoginAttempt(userAuth);

			userAuth = null;
			return false;
		}

		public bool TryAuthenticate(Dictionary<string, string> digestHeaders, string privateKey, int nonceTimeOut, string sequence, out IUserAuth userAuth)
		{
			//userId = null;
			userAuth = GetUserAuthByUserName(digestHeaders["username"]);
			if (userAuth == null)
				return false;

			var digestHelper = new DigestAuthFunctions();
			if (digestHelper.ValidateResponse(digestHeaders, privateKey, nonceTimeOut, userAuth.DigestHa1Hash, sequence))
			{
				this.RecordSuccessfulLogin(userAuth);

				return true;
			}

			this.RecordInvalidLoginAttempt(userAuth);

			userAuth = null;
			return false;
		}

		public void LoadUserAuth(IAuthSession session, IAuthTokens tokens)
		{
			if (session == null)
				throw new ArgumentNullException(nameof(session));

			var userAuth = GetUserAuth(session, tokens);
			LoadUserAuth(session, userAuth);
		}

		public IUserAuth GetUserAuth(string userAuthId)
		{
			var collection = _liteDatabase.GetCollection<UserAuth>(UserAuthCol);
			var userAuth = collection.Find(u => u.Id == int.Parse(userAuthId)).FirstOrDefault();
			return userAuth;
		}

		public void SaveUserAuth(IAuthSession authSession)
		{
			var userAuth = !authSession.UserAuthId.IsNullOrEmpty()
				? (UserAuth) GetUserAuth(authSession.UserAuthId)
				: authSession.ConvertTo<UserAuth>();

			if (userAuth.Id == default(int) && !authSession.UserAuthId.IsNullOrEmpty())
				userAuth.Id = int.Parse(authSession.UserAuthId);

			userAuth.ModifiedDate = DateTime.UtcNow;
			if (userAuth.CreatedDate == default(DateTime))
				userAuth.CreatedDate = userAuth.ModifiedDate;

			_liteDatabase.GetCollection<UserAuth>(UserAuthCol);
			SaveUser(userAuth);
		}

		public void SaveUserAuth(IUserAuth userAuth)
		{
			userAuth.ModifiedDate = DateTime.UtcNow;
			if (userAuth.CreatedDate == default(DateTime))
				userAuth.CreatedDate = userAuth.ModifiedDate;

			SaveUser(userAuth);
		}

		public void DeleteUserAuth(string userAuthId)
		{
			var userAuthCollection = _liteDatabase.GetCollection<UserAuth>(UserAuthCol);
			userAuthCollection.Delete(u => u.Id == int.Parse(userAuthId));

			var userAuthDetails = _liteDatabase.GetCollection<UserAuthDetails>(UserOAuthProviderCol);
			userAuthDetails.Delete(u => u.UserAuthId == int.Parse(userAuthId));
		}

		public List<IUserAuthDetails> GetUserAuthDetails(string userAuthId)
		{
			var collection = _liteDatabase.GetCollection<UserAuthDetails>(UserOAuthProviderCol);
			var queryResult = collection.Find(ud => ud.UserAuthId == int.Parse(userAuthId));
			return queryResult.ToList().Cast<IUserAuthDetails>().ToList();
		}

		public IUserAuth GetUserAuth(IAuthSession authSession, IAuthTokens tokens)
		{
			if (!authSession.UserAuthId.IsNullOrEmpty())
			{
				var userAuth = GetUserAuth(authSession.UserAuthId);
				if (userAuth != null) return userAuth;
			}
			if (!authSession.UserAuthName.IsNullOrEmpty())
			{
				var userAuth = GetUserAuthByUserName(authSession.UserAuthName);
				if (userAuth != null) return userAuth;
			}

			if (tokens == null || tokens.Provider.IsNullOrEmpty() || tokens.UserId.IsNullOrEmpty())
				return null;

			var providerCollection = _liteDatabase.GetCollection<UserAuthDetails>(UserOAuthProviderCol);
			var oAuthProvider = providerCollection.Find(ud => ud.Provider == tokens.Provider && ud.UserId == tokens.UserId).FirstOrDefault();

			if (oAuthProvider != null)
			{
				var userAuthCollection = _liteDatabase.GetCollection<UserAuth>(UserAuthCol);
				var userAuth = userAuthCollection.Find(u => u.Id == oAuthProvider.UserAuthId).FirstOrDefault();
				return userAuth;
			}
			return null;
		}

		public IUserAuthDetails CreateOrMergeAuthSession(IAuthSession authSession, IAuthTokens tokens)
		{
			var userAuth = GetUserAuth(authSession, tokens) ?? new UserAuth();

			var providerCollection = _liteDatabase.GetCollection<UserAuthDetails>(UserOAuthProviderCol);
			var authDetails = providerCollection.Find(ud => ud.Provider == tokens.Provider && ud.UserId == tokens.UserId).FirstOrDefault() ??
			                  new UserAuthDetails
			                  {
				                  Provider = tokens.Provider,
				                  UserId = tokens.UserId
			                  };

			authDetails.PopulateMissing(tokens);
			userAuth.PopulateMissingExtended(authDetails);

			userAuth.ModifiedDate = DateTime.UtcNow;
			if (userAuth.CreatedDate == default(DateTime))
				userAuth.CreatedDate = userAuth.ModifiedDate;

			SaveUser((UserAuth) userAuth);

			authDetails.UserAuthId = userAuth.Id;

			if (authDetails.CreatedDate == default(DateTime))
				authDetails.CreatedDate = userAuth.ModifiedDate;
			authDetails.ModifiedDate = userAuth.ModifiedDate;

			providerCollection.Update(authDetails);

			return authDetails;
		}

		public bool CollectionsExists()
		{
			var collectionNames = new List<string>
			{
				UserAuthCol,
				UserOAuthProviderCol
			};

			var collections = _liteDatabase.GetCollectionNames();
			return collections.Any(document => collectionNames.Contains(document));
		}

		public void CreateMissingCollections()
		{
			var collections = _liteDatabase.GetCollectionNames().ToList();

			if (!collections.Exists(document => document == UserAuthCol))
			{
				var collection = _liteDatabase.GetCollection<UserAuth>(UserAuthCol);
				collection.EnsureIndex(x => x.Email);
				collection.EnsureIndex(x => x.UserName);
			}

			if (!collections.Exists(document => document == UserOAuthProviderCol))
			{
				var collection = _liteDatabase.GetCollection<UserAuthDetails>(UserOAuthProviderCol);
				collection.EnsureIndex(x => x.UserAuthId);
			}
		}

		public void DropAndReCreateCollections()
		{
			_liteDatabase.DropCollection(UserAuthCol);
			_liteDatabase.DropCollection(UserOAuthProviderCol);

			CreateMissingCollections();
		}

		void SaveUser(IUserAuth userAuth)
		{
			var usersCollection = _liteDatabase.GetCollection<UserAuth>(UserAuthCol);
			if (userAuth.Id == default(int))
				usersCollection.Insert((UserAuth) userAuth);
			else
				usersCollection.Update((UserAuth) userAuth);
		}


		static void AssertNoExistingUser(LiteDatabase liteDatabase, IUserAuth newUser, IUserAuth exceptForExistingUser = null)
		{
			if (newUser.UserName != null)
			{
				var existingUser = GetUserAuthByUserName(liteDatabase, newUser.UserName);
				if (existingUser != null
				    && (exceptForExistingUser == null || existingUser.Id != exceptForExistingUser.Id))
					throw new ArgumentException(string.Format(ErrorMessages.UserAlreadyExistsTemplate1, newUser.UserName.SafeInput()));
			}
			if (newUser.Email != null)
			{
				var existingUser = GetUserAuthByUserName(liteDatabase, newUser.Email);
				if (existingUser != null
				    && (exceptForExistingUser == null || existingUser.Id != exceptForExistingUser.Id))
					throw new ArgumentException(string.Format(ErrorMessages.EmailAlreadyExistsTemplate1, newUser.Email.SafeInput()));
			}
		}

		static UserAuth GetUserAuthByUserName(LiteDatabase liteDatabase, string userNameOrEmail)
		{
			if (userNameOrEmail == null)
				return null;

			var isEmail = userNameOrEmail.Contains("@");
			var collection = liteDatabase.GetCollection<UserAuth>(UserAuthCol);

			var query = isEmail
				? Query.EQ(nameof(UserAuth.Email), userNameOrEmail)
				: Query.EQ(nameof(UserAuth.UserName), userNameOrEmail);

			var userAuth = collection.Find(query).FirstOrDefault();
			return userAuth;
		}

		void LoadUserAuth(IAuthSession session, IUserAuth userAuth)
		{
			session.PopulateSession(userAuth,
				GetUserAuthDetails(session.UserAuthId).ConvertAll(x => (IAuthTokens) x));
		}

		#region IManageApiKeys

		public void InitApiKeySchema()
		{
			var collections = _liteDatabase.GetCollectionNames().ToList();
			if (!collections.Exists(document => document == ApiKeysCol))
			{
				var collection = _liteDatabase.GetCollection<ApiKey>(ApiKeysCol);
				collection.EnsureIndex(x => x.UserAuthId);
			}
		}

		public bool ApiKeyExists(string apiKey)
		{
			if (string.IsNullOrEmpty(apiKey))
				return false;
			var collection = _liteDatabase.GetCollection<ApiKey>(ApiKeysCol);
			return collection.Count(key => key.Id == apiKey) > 0;
		}

		public ApiKey GetApiKey(string apiKey)
		{
			var collection = _liteDatabase.GetCollection<ApiKey>(ApiKeysCol);
			return collection.Find(key => key.Id == apiKey).FirstOrDefault();
		}

		public List<ApiKey> GetUserApiKeys(string userId)
		{
			var collection = _liteDatabase.GetCollection<ApiKey>(ApiKeysCol);
			var queryResult = collection.Find(key =>
				key.UserAuthId == userId
				&& key.CancelledDate == null
				&& (key.ExpiryDate == null || key.ExpiryDate >= DateTime.UtcNow));
			return queryResult.ToList();
		}

		public void StoreAll(IEnumerable<ApiKey> apiKeys)
		{
			var collection = _liteDatabase.GetCollection<ApiKey>(ApiKeysCol);

			foreach (var apiKey in apiKeys)
			{
				var found = collection.FindById(apiKey.Id);
				if (found == null)
					collection.Insert(apiKey);
				else
					collection.Update(apiKey);
			}
		}

		#endregion
	}
}