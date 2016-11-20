{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Auth.Server.Internal where

import           Control.Monad.Trans  (liftIO)
import           Servant              ((:>), Handler, HasServer (..),
                                       Proxy (..), HasContextEntry(getContextEntry))
import           Servant.Auth
import qualified Web.Cookie           as Cookie

import Servant.Auth.Server.Internal.AddSetCookie
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Types

import Servant.Server.Internal.RoutingApplication

instance ( HasServer (AddSetCookieApi api) ctxs, AreAuths auths ctxs v
         , AddSetCookie (ServerT api Handler) (ServerT (AddSetCookieApi api) Handler)
         , ToJWT v
         , HasContextEntry ctxs CookieSettings
         , HasContextEntry ctxs JWTSettings
         , Show v
         ) => HasServer (Auth auths v :> api) ctxs where
  type ServerT (Auth auths v :> api) m = AuthResult v -> ServerT api m

  route _ context subserver =
    route (Proxy :: Proxy (AddSetCookieApi api))
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (AuthResult v, [Cookie.SetCookie])
      authCheck = withRequest $ \req -> liftIO $ do
        authResult <- runAuthCheck (runAuths (Proxy :: Proxy auths) context) req
        csrf' <- csrfCookie
        let csrf = Cookie.def
             { Cookie.setCookieName = xsrfCookieName cookieSettings
             , Cookie.setCookieValue = csrf'
             , Cookie.setCookiePath = cookiePath cookieSettings
             , Cookie.setCookieMaxAge = cookieMaxAge cookieSettings
             , Cookie.setCookieExpires = cookieExpires cookieSettings
             , Cookie.setCookieSecure = case cookieIsSecure cookieSettings of
                  Secure -> True
                  NotSecure -> False
             }
        cookies <- makeCookies authResult
        return (authResult, csrf : cookies )

      jwtSettings :: JWTSettings
      jwtSettings = getContextEntry context

      cookieSettings :: CookieSettings
      cookieSettings = getContextEntry context

      makeCookies :: AuthResult v -> IO [Cookie.SetCookie]
      makeCookies (Authenticated v) = do
        ejwt <- makeCookie cookieSettings jwtSettings v
        case ejwt of
            Nothing  -> return []
            Just jwt -> return [jwt]
      makeCookies _ = return []


      -- See note in AddSetCookie.hs about what this is doing.
      go :: (old ~ ServerT api Handler
            , new ~ ServerT (AddSetCookieApi api) Handler
            ) => (AuthResult v -> ServerT api Handler)
         -> (AuthResult v, [Cookie.SetCookie]) -> new
      go fn (authResult, csrf) = addSetCookie csrf $ fn authResult
