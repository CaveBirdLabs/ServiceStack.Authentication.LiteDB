# ServiceStack.Authentication.LiteDB

LiteDB Auth provider for ServiceStack - If you want to use https://github.com/mbdavid/LiteDB as a ```IAuthRepository``` authorization implementation in ServiceStack.

## Install Package

```
Install-Package CaveBirdLabs.ServiceStack.Authentication.LiteDB
```

## How to register



```
container.Register(c => new LiteDatabase(@"MyData.db")).ReusedWithin(ReuseScope.Container);
container.Register<IAuthRepository>(c => 
                                    new LiteDBAuthRepository(container.Resolve<LiteDatabase>(), true));
```

