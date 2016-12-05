module Servant.Auth.Server.Internal.URLToken where
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT         (FromJWT (decodeJWT), ToJWT,
                                                 makeJWT)
import Servant.Auth.Server.Internal.Types
import GHC.TypeLits                             (KnownSymbol, symbolVal)
import           Blaze.ByteString.Builder (toByteString)
import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE              as Jose
import qualified Crypto.JWT               as Jose
import qualified Data.ByteString.Char8    as BSC
import qualified Data.ByteString.Lazy     as BSL
import           Network.Wai              (queryString)
import           Data.Proxy
import qualified Data.Map as M
import Debug.Trace




tokenAuthCheck :: (Show usr, FromJWT usr, KnownSymbol a) => Proxy a -> JWTSettings -> AuthCheck usr
tokenAuthCheck sym jwtCfg = do
  req <- ask
  traceShowM "tokenAuthCheck"
  let name = symbolVal sym
      qmap = traceShowId $ M.fromList $ queryString req
      qval = traceShowId $ join $ M.lookup (BSC.pack name) qmap
      jwtTok = maybe mempty id qval
  traceShowM "JWT"
  traceShowM jwtTok
  verifiedJWT <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict jwtTok
    Jose.validateJWSJWT (jwtSettingsToJwtValidationSettings jwtCfg)
                        (key jwtCfg)
                         unverifiedJWT
    return unverifiedJWT
  traceShowM "Verified"
  traceShowM verifiedJWT
  case verifiedJWT of
    Left (_ :: Jose.JWTError) -> mzero
    Right v -> case decodeJWT v of
      Left _ -> mzero
      Right v' -> return v'
