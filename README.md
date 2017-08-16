# ServiceStack.Authentication.LiteDB

LiteDB Auth provider for ServiceStack - If you want to use https://github.com/mbdavid/LiteDB as a ```IAuthRepository``` authorization implementation in ServiceStack.

## How to register

```
container.Register(c => new LiteDatabase(@"MyData.db")).ReusedWithin(ReuseScope.Container);
container.Register<IAuthRepository>(c => new LiteDBAuthRepository(container.Resolve<LiteDatabase>(), true));
```

