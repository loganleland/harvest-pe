import Data.HarvestPE
import qualified Data.ByteString.Lazy as BSL
import System.Environment

main = do
  args <- getArgs
  s <- BSL.readFile (head args)
  print $ harvest s
