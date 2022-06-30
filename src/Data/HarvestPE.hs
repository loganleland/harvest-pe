-----------------------------------------------------------------------------
-- |
-- Module      :  Data.HarvestPE
-- Copyright   :  (c) Logan Leland, 2022
-- License     :  MIT (see the file LICENSE)
--
-- Maintainer  :  Logan Leland <ethicalmath@gmail.com>
-- Stability   :  experimental
-- Portability :  portable
--
-- Harvest (parse) the PE format.
--
-----------------------------------------------------------------------------

module Data.HarvestPE
  (
    PE,
    harvest
  ) where

import Data.Word
import qualified Data.Binary.Get as G
import qualified Data.ByteString.Lazy as BSL
import qualified Data.HarvestSection as S
import qualified Data.HarvestNTHeader as NT
import qualified Data.HarvestDOSHeader as DOS

data PE = PE
  { dHeader :: DOS.DOSHeader
  , ntHeader :: NT.NTHeader
  , sections :: [S.Section]
  }
  deriving Show

harvest :: BSL.ByteString -> PE
harvest a = do
  let dHeader' = DOS.harvest a
  let ntHeader' = NT.harvest (fromIntegral $ DOS.e_lfanew dHeader') a
  let optSize = if (fromIntegral $ NT.optMagic $ NT.optHeader ntHeader') == 267 then 224 else 240
  let sections' = S.harvest ((4+20+optSize) + (fromIntegral $ DOS.e_lfanew dHeader')) (fromIntegral $ NT.numSection $ NT.fHeader ntHeader') a
  PE { dHeader = dHeader'
     , ntHeader = ntHeader'
     , sections = sections'
     }
