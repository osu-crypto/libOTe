/*
Copyright (C) 2018 Wen-Ding Li

This file is part of BitPolyMul.

BitPolyMul is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

BitPolyMul is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with BitPolyMul.  If not, see <http://www.gnu.org/licenses/>.
*/
 

#include "libOTe/config.h"
#ifdef ENABLE_SILENTOT

#include "bc_to_gen_code.h"
namespace bpm {
void bc_to_lch_256_30_12(__m256i* poly, int logn){
for(int offset=(1<<30);offset<(1<<logn);offset+=(1<<(30+1))){
for(int i=offset+(1<<30)-1-805306368;i>=offset+(1<<30)-1006632960;--i)xorEq(poly[i],poly[i+805306368]);
for(int i=offset+(1<<30)-1-1006632960;i>=offset+(1<<30)-1056964608;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960]);
for(int i=offset+(1<<30)-1-1056964608;i>=offset+(1<<30)-1069547520;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608]);
for(int i=offset+(1<<30)-1-1069547520;i>=offset+(1<<30)-1072693248;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520]);
for(int i=offset+(1<<30)-1-1072693248;i>=offset+(1<<30)-1073479680;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248]);
for(int i=offset+(1<<30)-1-1073479680;i>=offset+(1<<30)-1073676288;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680]);
for(int i=offset+(1<<30)-1-1073676288;i>=offset+(1<<30)-1073725440;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288]);
for(int i=offset+(1<<30)-1-1073725440;i>=offset+(1<<30)-1073737728;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440]);
for(int i=offset+(1<<30)-1-1073737728;i>=offset+(1<<30)-1073740800;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728]);
for(int i=offset+(1<<30)-1-1073740800;i>=offset+(1<<30)-1073741568;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800]);
for(int i=offset+(1<<30)-1-1073741568;i>=offset+(1<<30)-1073741760;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568]);
for(int i=offset+(1<<30)-1-1073741760;i>=offset+(1<<30)-1073741808;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760]);
for(int i=offset+(1<<30)-1-1073741808;i>=offset+(1<<30)-1073741820;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808]);
for(int i=offset+(1<<30)-1-1073741820;i>=offset+(1<<30)-1073741823;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820]);
for(int i=offset+(1<<30)-1-1073741823;i>=offset+(1<<30)-1073741824;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-0;i>=offset-805306368;--i)xorEq(poly[i],poly[i+805306368],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-805306368;i>=offset-1006632960;--i)xorEq(poly[i],poly[i+1006632960],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1006632960;i>=offset-1056964608;--i)xorEq(poly[i],poly[i+1056964608],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1056964608;i>=offset-1069547520;--i)xorEq(poly[i],poly[i+1069547520],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1069547520;i>=offset-1072693248;--i)xorEq(poly[i],poly[i+1072693248],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1072693248;i>=offset-1073479680;--i)xorEq(poly[i],poly[i+1073479680],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1073479680;i>=offset-1073676288;--i)xorEq(poly[i],poly[i+1073676288],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1073676288;i>=offset-1073725440;--i)xorEq(poly[i],poly[i+1073725440],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1073725440;i>=offset-1073737728;--i)xorEq(poly[i],poly[i+1073737728],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1073737728;i>=offset-1073740800;--i)xorEq(poly[i],poly[i+1073740800],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1073740800;i>=offset-1073741568;--i)xorEq(poly[i],poly[i+1073741568],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1073741568;i>=offset-1073741760;--i)xorEq(poly[i],poly[i+1073741760],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1073741760;i>=offset-1073741808;--i)xorEq(poly[i],poly[i+1073741808],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1073741808;i>=offset-1073741820;--i)xorEq(poly[i],poly[i+1073741820],poly[i+1073741823]);
for(int i=offset-1-1073741820;i>=offset-1073741823;--i)xorEq(poly[i],poly[i+1073741823]);

}
for(int offset=(1<<29);offset<(1<<logn);offset+=(1<<(29+1))){
for(int i=offset+(1<<29)-1-268435456;i>=offset+(1<<29)-503316480;--i)xorEq(poly[i],poly[i+268435456]);
for(int i=offset+(1<<29)-1-503316480;i>=offset+(1<<29)-520093696;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480]);
for(int i=offset+(1<<29)-1-520093696;i>=offset+(1<<29)-534773760;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696]);
for(int i=offset+(1<<29)-1-534773760;i>=offset+(1<<29)-535822336;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760]);
for(int i=offset+(1<<29)-1-535822336;i>=offset+(1<<29)-536739840;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336]);
for(int i=offset+(1<<29)-1-536739840;i>=offset+(1<<29)-536805376;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840]);
for(int i=offset+(1<<29)-1-536805376;i>=offset+(1<<29)-536862720;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376]);
for(int i=offset+(1<<29)-1-536862720;i>=offset+(1<<29)-536866816;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720]);
for(int i=offset+(1<<29)-1-536866816;i>=offset+(1<<29)-536870400;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816]);
for(int i=offset+(1<<29)-1-536870400;i>=offset+(1<<29)-536870656;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400]);
for(int i=offset+(1<<29)-1-536870656;i>=offset+(1<<29)-536870880;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656]);
for(int i=offset+(1<<29)-1-536870880;i>=offset+(1<<29)-536870896;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880]);
for(int i=offset+(1<<29)-1-536870896;i>=offset+(1<<29)-536870910;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896]);
for(int i=offset+(1<<29)-1-536870910;i>=offset+(1<<29)-536870911;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910]);
for(int i=offset+(1<<29)-1-536870911;i>=offset+(1<<29)-536870912;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-0;i>=offset-268435456;--i)xorEq(poly[i],poly[i+268435456],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-268435456;i>=offset-503316480;--i)xorEq(poly[i],poly[i+503316480],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-503316480;i>=offset-520093696;--i)xorEq(poly[i],poly[i+520093696],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-520093696;i>=offset-534773760;--i)xorEq(poly[i],poly[i+534773760],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-534773760;i>=offset-535822336;--i)xorEq(poly[i],poly[i+535822336],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-535822336;i>=offset-536739840;--i)xorEq(poly[i],poly[i+536739840],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-536739840;i>=offset-536805376;--i)xorEq(poly[i],poly[i+536805376],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-536805376;i>=offset-536862720;--i)xorEq(poly[i],poly[i+536862720],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-536862720;i>=offset-536866816;--i)xorEq(poly[i],poly[i+536866816],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-536866816;i>=offset-536870400;--i)xorEq(poly[i],poly[i+536870400],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-536870400;i>=offset-536870656;--i)xorEq(poly[i],poly[i+536870656],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-536870656;i>=offset-536870880;--i)xorEq(poly[i],poly[i+536870880],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-536870880;i>=offset-536870896;--i)xorEq(poly[i],poly[i+536870896],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-536870896;i>=offset-536870910;--i)xorEq(poly[i],poly[i+536870910],poly[i+536870911]);
for(int i=offset-1-536870910;i>=offset-536870911;--i)xorEq(poly[i],poly[i+536870911]);

}
for(int offset=(1<<28);offset<(1<<logn);offset+=(1<<(28+1))){
for(int i=offset+(1<<28)-1-251658240;i>=offset+(1<<28)-267386880;--i)xorEq(poly[i],poly[i+251658240]);
for(int i=offset+(1<<28)-1-267386880;i>=offset+(1<<28)-268369920;--i)xorEq(poly[i],poly[i+251658240],poly[i+267386880]);
for(int i=offset+(1<<28)-1-268369920;i>=offset+(1<<28)-268431360;--i)xorEq(poly[i],poly[i+251658240],poly[i+267386880],poly[i+268369920]);
for(int i=offset+(1<<28)-1-268431360;i>=offset+(1<<28)-268435200;--i)xorEq(poly[i],poly[i+251658240],poly[i+267386880],poly[i+268369920],poly[i+268431360]);
for(int i=offset+(1<<28)-1-268435200;i>=offset+(1<<28)-268435440;--i)xorEq(poly[i],poly[i+251658240],poly[i+267386880],poly[i+268369920],poly[i+268431360],poly[i+268435200]);
for(int i=offset+(1<<28)-1-268435440;i>=offset+(1<<28)-268435455;--i)xorEq(poly[i],poly[i+251658240],poly[i+267386880],poly[i+268369920],poly[i+268431360],poly[i+268435200],poly[i+268435440]);
for(int i=offset+(1<<28)-1-268435455;i>=offset+(1<<28)-268435456;--i)xorEq(poly[i],poly[i+251658240],poly[i+267386880],poly[i+268369920],poly[i+268431360],poly[i+268435200],poly[i+268435440],poly[i+268435455]);
for(int i=offset-1-0;i>=offset-251658240;--i)xorEq(poly[i],poly[i+251658240],poly[i+267386880],poly[i+268369920],poly[i+268431360],poly[i+268435200],poly[i+268435440],poly[i+268435455]);
for(int i=offset-1-251658240;i>=offset-267386880;--i)xorEq(poly[i],poly[i+267386880],poly[i+268369920],poly[i+268431360],poly[i+268435200],poly[i+268435440],poly[i+268435455]);
for(int i=offset-1-267386880;i>=offset-268369920;--i)xorEq(poly[i],poly[i+268369920],poly[i+268431360],poly[i+268435200],poly[i+268435440],poly[i+268435455]);
for(int i=offset-1-268369920;i>=offset-268431360;--i)xorEq(poly[i],poly[i+268431360],poly[i+268435200],poly[i+268435440],poly[i+268435455]);
for(int i=offset-1-268431360;i>=offset-268435200;--i)xorEq(poly[i],poly[i+268435200],poly[i+268435440],poly[i+268435455]);
for(int i=offset-1-268435200;i>=offset-268435440;--i)xorEq(poly[i],poly[i+268435440],poly[i+268435455]);
for(int i=offset-1-268435440;i>=offset-268435455;--i)xorEq(poly[i],poly[i+268435455]);

}
for(int offset=(1<<27);offset<(1<<logn);offset+=(1<<(27+1))){
for(int i=offset+(1<<27)-1-67108864;i>=offset+(1<<27)-100663296;--i)xorEq(poly[i],poly[i+67108864]);
for(int i=offset+(1<<27)-1-100663296;i>=offset+(1<<27)-117440512;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296]);
for(int i=offset+(1<<27)-1-117440512;i>=offset+(1<<27)-133693440;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512]);
for(int i=offset+(1<<27)-1-133693440;i>=offset+(1<<27)-133955584;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440]);
for(int i=offset+(1<<27)-1-133955584;i>=offset+(1<<27)-134086656;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584]);
for(int i=offset+(1<<27)-1-134086656;i>=offset+(1<<27)-134152192;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656]);
for(int i=offset+(1<<27)-1-134152192;i>=offset+(1<<27)-134215680;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192]);
for(int i=offset+(1<<27)-1-134215680;i>=offset+(1<<27)-134216704;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680]);
for(int i=offset+(1<<27)-1-134216704;i>=offset+(1<<27)-134217216;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704]);
for(int i=offset+(1<<27)-1-134217216;i>=offset+(1<<27)-134217472;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216]);
for(int i=offset+(1<<27)-1-134217472;i>=offset+(1<<27)-134217720;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472]);
for(int i=offset+(1<<27)-1-134217720;i>=offset+(1<<27)-134217724;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720]);
for(int i=offset+(1<<27)-1-134217724;i>=offset+(1<<27)-134217726;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724]);
for(int i=offset+(1<<27)-1-134217726;i>=offset+(1<<27)-134217727;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726]);
for(int i=offset+(1<<27)-1-134217727;i>=offset+(1<<27)-134217728;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-0;i>=offset-67108864;--i)xorEq(poly[i],poly[i+67108864],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-67108864;i>=offset-100663296;--i)xorEq(poly[i],poly[i+100663296],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-100663296;i>=offset-117440512;--i)xorEq(poly[i],poly[i+117440512],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-117440512;i>=offset-133693440;--i)xorEq(poly[i],poly[i+133693440],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-133693440;i>=offset-133955584;--i)xorEq(poly[i],poly[i+133955584],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-133955584;i>=offset-134086656;--i)xorEq(poly[i],poly[i+134086656],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-134086656;i>=offset-134152192;--i)xorEq(poly[i],poly[i+134152192],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-134152192;i>=offset-134215680;--i)xorEq(poly[i],poly[i+134215680],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-134215680;i>=offset-134216704;--i)xorEq(poly[i],poly[i+134216704],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-134216704;i>=offset-134217216;--i)xorEq(poly[i],poly[i+134217216],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-134217216;i>=offset-134217472;--i)xorEq(poly[i],poly[i+134217472],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-134217472;i>=offset-134217720;--i)xorEq(poly[i],poly[i+134217720],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-134217720;i>=offset-134217724;--i)xorEq(poly[i],poly[i+134217724],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-134217724;i>=offset-134217726;--i)xorEq(poly[i],poly[i+134217726],poly[i+134217727]);
for(int i=offset-1-134217726;i>=offset-134217727;--i)xorEq(poly[i],poly[i+134217727]);

}
for(int offset=(1<<26);offset<(1<<logn);offset+=(1<<(26+1))){
for(int i=offset+(1<<26)-1-50331648;i>=offset+(1<<26)-66846720;--i)xorEq(poly[i],poly[i+50331648]);
for(int i=offset+(1<<26)-1-66846720;i>=offset+(1<<26)-67043328;--i)xorEq(poly[i],poly[i+50331648],poly[i+66846720]);
for(int i=offset+(1<<26)-1-67043328;i>=offset+(1<<26)-67107840;--i)xorEq(poly[i],poly[i+50331648],poly[i+66846720],poly[i+67043328]);
for(int i=offset+(1<<26)-1-67107840;i>=offset+(1<<26)-67108608;--i)xorEq(poly[i],poly[i+50331648],poly[i+66846720],poly[i+67043328],poly[i+67107840]);
for(int i=offset+(1<<26)-1-67108608;i>=offset+(1<<26)-67108860;--i)xorEq(poly[i],poly[i+50331648],poly[i+66846720],poly[i+67043328],poly[i+67107840],poly[i+67108608]);
for(int i=offset+(1<<26)-1-67108860;i>=offset+(1<<26)-67108863;--i)xorEq(poly[i],poly[i+50331648],poly[i+66846720],poly[i+67043328],poly[i+67107840],poly[i+67108608],poly[i+67108860]);
for(int i=offset+(1<<26)-1-67108863;i>=offset+(1<<26)-67108864;--i)xorEq(poly[i],poly[i+50331648],poly[i+66846720],poly[i+67043328],poly[i+67107840],poly[i+67108608],poly[i+67108860],poly[i+67108863]);
for(int i=offset-1-0;i>=offset-50331648;--i)xorEq(poly[i],poly[i+50331648],poly[i+66846720],poly[i+67043328],poly[i+67107840],poly[i+67108608],poly[i+67108860],poly[i+67108863]);
for(int i=offset-1-50331648;i>=offset-66846720;--i)xorEq(poly[i],poly[i+66846720],poly[i+67043328],poly[i+67107840],poly[i+67108608],poly[i+67108860],poly[i+67108863]);
for(int i=offset-1-66846720;i>=offset-67043328;--i)xorEq(poly[i],poly[i+67043328],poly[i+67107840],poly[i+67108608],poly[i+67108860],poly[i+67108863]);
for(int i=offset-1-67043328;i>=offset-67107840;--i)xorEq(poly[i],poly[i+67107840],poly[i+67108608],poly[i+67108860],poly[i+67108863]);
for(int i=offset-1-67107840;i>=offset-67108608;--i)xorEq(poly[i],poly[i+67108608],poly[i+67108860],poly[i+67108863]);
for(int i=offset-1-67108608;i>=offset-67108860;--i)xorEq(poly[i],poly[i+67108860],poly[i+67108863]);
for(int i=offset-1-67108860;i>=offset-67108863;--i)xorEq(poly[i],poly[i+67108863]);

}
for(int offset=(1<<25);offset<(1<<logn);offset+=(1<<(25+1))){
for(int i=offset+(1<<25)-1-16777216;i>=offset+(1<<25)-33423360;--i)xorEq(poly[i],poly[i+16777216]);
for(int i=offset+(1<<25)-1-33423360;i>=offset+(1<<25)-33488896;--i)xorEq(poly[i],poly[i+16777216],poly[i+33423360]);
for(int i=offset+(1<<25)-1-33488896;i>=offset+(1<<25)-33553920;--i)xorEq(poly[i],poly[i+16777216],poly[i+33423360],poly[i+33488896]);
for(int i=offset+(1<<25)-1-33553920;i>=offset+(1<<25)-33554176;--i)xorEq(poly[i],poly[i+16777216],poly[i+33423360],poly[i+33488896],poly[i+33553920]);
for(int i=offset+(1<<25)-1-33554176;i>=offset+(1<<25)-33554430;--i)xorEq(poly[i],poly[i+16777216],poly[i+33423360],poly[i+33488896],poly[i+33553920],poly[i+33554176]);
for(int i=offset+(1<<25)-1-33554430;i>=offset+(1<<25)-33554431;--i)xorEq(poly[i],poly[i+16777216],poly[i+33423360],poly[i+33488896],poly[i+33553920],poly[i+33554176],poly[i+33554430]);
for(int i=offset+(1<<25)-1-33554431;i>=offset+(1<<25)-33554432;--i)xorEq(poly[i],poly[i+16777216],poly[i+33423360],poly[i+33488896],poly[i+33553920],poly[i+33554176],poly[i+33554430],poly[i+33554431]);
for(int i=offset-1-0;i>=offset-16777216;--i)xorEq(poly[i],poly[i+16777216],poly[i+33423360],poly[i+33488896],poly[i+33553920],poly[i+33554176],poly[i+33554430],poly[i+33554431]);
for(int i=offset-1-16777216;i>=offset-33423360;--i)xorEq(poly[i],poly[i+33423360],poly[i+33488896],poly[i+33553920],poly[i+33554176],poly[i+33554430],poly[i+33554431]);
for(int i=offset-1-33423360;i>=offset-33488896;--i)xorEq(poly[i],poly[i+33488896],poly[i+33553920],poly[i+33554176],poly[i+33554430],poly[i+33554431]);
for(int i=offset-1-33488896;i>=offset-33553920;--i)xorEq(poly[i],poly[i+33553920],poly[i+33554176],poly[i+33554430],poly[i+33554431]);
for(int i=offset-1-33553920;i>=offset-33554176;--i)xorEq(poly[i],poly[i+33554176],poly[i+33554430],poly[i+33554431]);
for(int i=offset-1-33554176;i>=offset-33554430;--i)xorEq(poly[i],poly[i+33554430],poly[i+33554431]);
for(int i=offset-1-33554430;i>=offset-33554431;--i)xorEq(poly[i],poly[i+33554431]);

}
for(int offset=(1<<24);offset<(1<<logn);offset+=(1<<(24+1))){
for(int i=offset+(1<<24)-1-16711680;i>=offset+(1<<24)-16776960;--i)xorEq(poly[i],poly[i+16711680]);
for(int i=offset+(1<<24)-1-16776960;i>=offset+(1<<24)-16777215;--i)xorEq(poly[i],poly[i+16711680],poly[i+16776960]);
for(int i=offset+(1<<24)-1-16777215;i>=offset+(1<<24)-16777216;--i)xorEq(poly[i],poly[i+16711680],poly[i+16776960],poly[i+16777215]);
for(int i=offset-1-0;i>=offset-16711680;--i)xorEq(poly[i],poly[i+16711680],poly[i+16776960],poly[i+16777215]);
for(int i=offset-1-16711680;i>=offset-16776960;--i)xorEq(poly[i],poly[i+16776960],poly[i+16777215]);
for(int i=offset-1-16776960;i>=offset-16777215;--i)xorEq(poly[i],poly[i+16777215]);

}
for(int offset=(1<<23);offset<(1<<logn);offset+=(1<<(23+1))){
for(int i=offset+(1<<23)-1-4194304;i>=offset+(1<<23)-6291456;--i)xorEq(poly[i],poly[i+4194304]);
for(int i=offset+(1<<23)-1-6291456;i>=offset+(1<<23)-7340032;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456]);
for(int i=offset+(1<<23)-1-7340032;i>=offset+(1<<23)-7864320;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032]);
for(int i=offset+(1<<23)-1-7864320;i>=offset+(1<<23)-8126464;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320]);
for(int i=offset+(1<<23)-1-8126464;i>=offset+(1<<23)-8257536;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464]);
for(int i=offset+(1<<23)-1-8257536;i>=offset+(1<<23)-8323072;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536]);
for(int i=offset+(1<<23)-1-8323072;i>=offset+(1<<23)-8388480;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072]);
for(int i=offset+(1<<23)-1-8388480;i>=offset+(1<<23)-8388544;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480]);
for(int i=offset+(1<<23)-1-8388544;i>=offset+(1<<23)-8388576;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544]);
for(int i=offset+(1<<23)-1-8388576;i>=offset+(1<<23)-8388592;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576]);
for(int i=offset+(1<<23)-1-8388592;i>=offset+(1<<23)-8388600;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592]);
for(int i=offset+(1<<23)-1-8388600;i>=offset+(1<<23)-8388604;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600]);
for(int i=offset+(1<<23)-1-8388604;i>=offset+(1<<23)-8388606;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604]);
for(int i=offset+(1<<23)-1-8388606;i>=offset+(1<<23)-8388607;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606]);
for(int i=offset+(1<<23)-1-8388607;i>=offset+(1<<23)-8388608;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-0;i>=offset-4194304;--i)xorEq(poly[i],poly[i+4194304],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-4194304;i>=offset-6291456;--i)xorEq(poly[i],poly[i+6291456],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-6291456;i>=offset-7340032;--i)xorEq(poly[i],poly[i+7340032],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-7340032;i>=offset-7864320;--i)xorEq(poly[i],poly[i+7864320],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-7864320;i>=offset-8126464;--i)xorEq(poly[i],poly[i+8126464],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8126464;i>=offset-8257536;--i)xorEq(poly[i],poly[i+8257536],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8257536;i>=offset-8323072;--i)xorEq(poly[i],poly[i+8323072],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8323072;i>=offset-8388480;--i)xorEq(poly[i],poly[i+8388480],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8388480;i>=offset-8388544;--i)xorEq(poly[i],poly[i+8388544],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8388544;i>=offset-8388576;--i)xorEq(poly[i],poly[i+8388576],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8388576;i>=offset-8388592;--i)xorEq(poly[i],poly[i+8388592],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8388592;i>=offset-8388600;--i)xorEq(poly[i],poly[i+8388600],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8388600;i>=offset-8388604;--i)xorEq(poly[i],poly[i+8388604],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8388604;i>=offset-8388606;--i)xorEq(poly[i],poly[i+8388606],poly[i+8388607]);
for(int i=offset-1-8388606;i>=offset-8388607;--i)xorEq(poly[i],poly[i+8388607]);

}
for(int offset=(1<<22);offset<(1<<logn);offset+=(1<<(22+1))){
for(int i=offset+(1<<22)-1-3145728;i>=offset+(1<<22)-3932160;--i)xorEq(poly[i],poly[i+3145728]);
for(int i=offset+(1<<22)-1-3932160;i>=offset+(1<<22)-4128768;--i)xorEq(poly[i],poly[i+3145728],poly[i+3932160]);
for(int i=offset+(1<<22)-1-4128768;i>=offset+(1<<22)-4194240;--i)xorEq(poly[i],poly[i+3145728],poly[i+3932160],poly[i+4128768]);
for(int i=offset+(1<<22)-1-4194240;i>=offset+(1<<22)-4194288;--i)xorEq(poly[i],poly[i+3145728],poly[i+3932160],poly[i+4128768],poly[i+4194240]);
for(int i=offset+(1<<22)-1-4194288;i>=offset+(1<<22)-4194300;--i)xorEq(poly[i],poly[i+3145728],poly[i+3932160],poly[i+4128768],poly[i+4194240],poly[i+4194288]);
for(int i=offset+(1<<22)-1-4194300;i>=offset+(1<<22)-4194303;--i)xorEq(poly[i],poly[i+3145728],poly[i+3932160],poly[i+4128768],poly[i+4194240],poly[i+4194288],poly[i+4194300]);
for(int i=offset+(1<<22)-1-4194303;i>=offset+(1<<22)-4194304;--i)xorEq(poly[i],poly[i+3145728],poly[i+3932160],poly[i+4128768],poly[i+4194240],poly[i+4194288],poly[i+4194300],poly[i+4194303]);
for(int i=offset-1-0;i>=offset-3145728;--i)xorEq(poly[i],poly[i+3145728],poly[i+3932160],poly[i+4128768],poly[i+4194240],poly[i+4194288],poly[i+4194300],poly[i+4194303]);
for(int i=offset-1-3145728;i>=offset-3932160;--i)xorEq(poly[i],poly[i+3932160],poly[i+4128768],poly[i+4194240],poly[i+4194288],poly[i+4194300],poly[i+4194303]);
for(int i=offset-1-3932160;i>=offset-4128768;--i)xorEq(poly[i],poly[i+4128768],poly[i+4194240],poly[i+4194288],poly[i+4194300],poly[i+4194303]);
for(int i=offset-1-4128768;i>=offset-4194240;--i)xorEq(poly[i],poly[i+4194240],poly[i+4194288],poly[i+4194300],poly[i+4194303]);
for(int i=offset-1-4194240;i>=offset-4194288;--i)xorEq(poly[i],poly[i+4194288],poly[i+4194300],poly[i+4194303]);
for(int i=offset-1-4194288;i>=offset-4194300;--i)xorEq(poly[i],poly[i+4194300],poly[i+4194303]);
for(int i=offset-1-4194300;i>=offset-4194303;--i)xorEq(poly[i],poly[i+4194303]);

}
for(int offset=(1<<21);offset<(1<<logn);offset+=(1<<(21+1))){
for(int i=offset+(1<<21)-1-1048576;i>=offset+(1<<21)-1966080;--i)xorEq(poly[i],poly[i+1048576]);
for(int i=offset+(1<<21)-1-1966080;i>=offset+(1<<21)-2031616;--i)xorEq(poly[i],poly[i+1048576],poly[i+1966080]);
for(int i=offset+(1<<21)-1-2031616;i>=offset+(1<<21)-2097120;--i)xorEq(poly[i],poly[i+1048576],poly[i+1966080],poly[i+2031616]);
for(int i=offset+(1<<21)-1-2097120;i>=offset+(1<<21)-2097136;--i)xorEq(poly[i],poly[i+1048576],poly[i+1966080],poly[i+2031616],poly[i+2097120]);
for(int i=offset+(1<<21)-1-2097136;i>=offset+(1<<21)-2097150;--i)xorEq(poly[i],poly[i+1048576],poly[i+1966080],poly[i+2031616],poly[i+2097120],poly[i+2097136]);
for(int i=offset+(1<<21)-1-2097150;i>=offset+(1<<21)-2097151;--i)xorEq(poly[i],poly[i+1048576],poly[i+1966080],poly[i+2031616],poly[i+2097120],poly[i+2097136],poly[i+2097150]);
for(int i=offset+(1<<21)-1-2097151;i>=offset+(1<<21)-2097152;--i)xorEq(poly[i],poly[i+1048576],poly[i+1966080],poly[i+2031616],poly[i+2097120],poly[i+2097136],poly[i+2097150],poly[i+2097151]);
for(int i=offset-1-0;i>=offset-1048576;--i)xorEq(poly[i],poly[i+1048576],poly[i+1966080],poly[i+2031616],poly[i+2097120],poly[i+2097136],poly[i+2097150],poly[i+2097151]);
for(int i=offset-1-1048576;i>=offset-1966080;--i)xorEq(poly[i],poly[i+1966080],poly[i+2031616],poly[i+2097120],poly[i+2097136],poly[i+2097150],poly[i+2097151]);
for(int i=offset-1-1966080;i>=offset-2031616;--i)xorEq(poly[i],poly[i+2031616],poly[i+2097120],poly[i+2097136],poly[i+2097150],poly[i+2097151]);
for(int i=offset-1-2031616;i>=offset-2097120;--i)xorEq(poly[i],poly[i+2097120],poly[i+2097136],poly[i+2097150],poly[i+2097151]);
for(int i=offset-1-2097120;i>=offset-2097136;--i)xorEq(poly[i],poly[i+2097136],poly[i+2097150],poly[i+2097151]);
for(int i=offset-1-2097136;i>=offset-2097150;--i)xorEq(poly[i],poly[i+2097150],poly[i+2097151]);
for(int i=offset-1-2097150;i>=offset-2097151;--i)xorEq(poly[i],poly[i+2097151]);

}
for(int offset=(1<<20);offset<(1<<logn);offset+=(1<<(20+1))){
for(int i=offset+(1<<20)-1-983040;i>=offset+(1<<20)-1048560;--i)xorEq(poly[i],poly[i+983040]);
for(int i=offset+(1<<20)-1-1048560;i>=offset+(1<<20)-1048575;--i)xorEq(poly[i],poly[i+983040],poly[i+1048560]);
for(int i=offset+(1<<20)-1-1048575;i>=offset+(1<<20)-1048576;--i)xorEq(poly[i],poly[i+983040],poly[i+1048560],poly[i+1048575]);
for(int i=offset-1-0;i>=offset-983040;--i)xorEq(poly[i],poly[i+983040],poly[i+1048560],poly[i+1048575]);
for(int i=offset-1-983040;i>=offset-1048560;--i)xorEq(poly[i],poly[i+1048560],poly[i+1048575]);
for(int i=offset-1-1048560;i>=offset-1048575;--i)xorEq(poly[i],poly[i+1048575]);

}
for(int offset=(1<<19);offset<(1<<logn);offset+=(1<<(19+1))){
for(int i=offset+(1<<19)-1-262144;i>=offset+(1<<19)-393216;--i)xorEq(poly[i],poly[i+262144]);
for(int i=offset+(1<<19)-1-393216;i>=offset+(1<<19)-458752;--i)xorEq(poly[i],poly[i+262144],poly[i+393216]);
for(int i=offset+(1<<19)-1-458752;i>=offset+(1<<19)-524280;--i)xorEq(poly[i],poly[i+262144],poly[i+393216],poly[i+458752]);
for(int i=offset+(1<<19)-1-524280;i>=offset+(1<<19)-524284;--i)xorEq(poly[i],poly[i+262144],poly[i+393216],poly[i+458752],poly[i+524280]);
for(int i=offset+(1<<19)-1-524284;i>=offset+(1<<19)-524286;--i)xorEq(poly[i],poly[i+262144],poly[i+393216],poly[i+458752],poly[i+524280],poly[i+524284]);
for(int i=offset+(1<<19)-1-524286;i>=offset+(1<<19)-524287;--i)xorEq(poly[i],poly[i+262144],poly[i+393216],poly[i+458752],poly[i+524280],poly[i+524284],poly[i+524286]);
for(int i=offset+(1<<19)-1-524287;i>=offset+(1<<19)-524288;--i)xorEq(poly[i],poly[i+262144],poly[i+393216],poly[i+458752],poly[i+524280],poly[i+524284],poly[i+524286],poly[i+524287]);
for(int i=offset-1-0;i>=offset-262144;--i)xorEq(poly[i],poly[i+262144],poly[i+393216],poly[i+458752],poly[i+524280],poly[i+524284],poly[i+524286],poly[i+524287]);
for(int i=offset-1-262144;i>=offset-393216;--i)xorEq(poly[i],poly[i+393216],poly[i+458752],poly[i+524280],poly[i+524284],poly[i+524286],poly[i+524287]);
for(int i=offset-1-393216;i>=offset-458752;--i)xorEq(poly[i],poly[i+458752],poly[i+524280],poly[i+524284],poly[i+524286],poly[i+524287]);
for(int i=offset-1-458752;i>=offset-524280;--i)xorEq(poly[i],poly[i+524280],poly[i+524284],poly[i+524286],poly[i+524287]);
for(int i=offset-1-524280;i>=offset-524284;--i)xorEq(poly[i],poly[i+524284],poly[i+524286],poly[i+524287]);
for(int i=offset-1-524284;i>=offset-524286;--i)xorEq(poly[i],poly[i+524286],poly[i+524287]);
for(int i=offset-1-524286;i>=offset-524287;--i)xorEq(poly[i],poly[i+524287]);

}
}

void bc_to_lch_256_19_17(__m256i* poly, int logn){
for(int offset=(1<<18);offset<(1<<logn);offset+=(1<<(18+1))){
for(int i=offset+(1<<18)-1-196608;i>=offset+(1<<18)-262140;--i)xorEq(poly[i],poly[i+196608]);
for(int i=offset+(1<<18)-1-262140;i>=offset+(1<<18)-262143;--i)xorEq(poly[i],poly[i+196608],poly[i+262140]);
for(int i=offset+(1<<18)-1-262143;i>=offset+(1<<18)-262144;--i)xorEq(poly[i],poly[i+196608],poly[i+262140],poly[i+262143]);
for(int i=offset-1-0;i>=offset-196608;--i)xorEq(poly[i],poly[i+196608],poly[i+262140],poly[i+262143]);
for(int i=offset-1-196608;i>=offset-262140;--i)xorEq(poly[i],poly[i+262140],poly[i+262143]);
for(int i=offset-1-262140;i>=offset-262143;--i)xorEq(poly[i],poly[i+262143]);

}
for(int offset=(1<<17);offset<(1<<logn);offset+=(1<<(17+1))){
for(int i=offset+(1<<17)-1-65536;i>=offset+(1<<17)-131070;--i)xorEq(poly[i],poly[i+65536]);
for(int i=offset+(1<<17)-1-131070;i>=offset+(1<<17)-131071;--i)xorEq(poly[i],poly[i+65536],poly[i+131070]);
for(int i=offset+(1<<17)-1-131071;i>=offset+(1<<17)-131072;--i)xorEq(poly[i],poly[i+65536],poly[i+131070],poly[i+131071]);
for(int i=offset-1-0;i>=offset-65536;--i)xorEq(poly[i],poly[i+65536],poly[i+131070],poly[i+131071]);
for(int i=offset-1-65536;i>=offset-131070;--i)xorEq(poly[i],poly[i+131070],poly[i+131071]);
for(int i=offset-1-131070;i>=offset-131071;--i)xorEq(poly[i],poly[i+131071]);

}
for(int offset=(1<<16);offset<(1<<logn);offset+=(1<<(16+1))){
for(int i=offset+(1<<16)-1-65535;i>=offset+(1<<16)-65536;--i)xorEq(poly[i],poly[i+65535]);
for(int i=offset-1-0;i>=offset-65535;--i)xorEq(poly[i],poly[i+65535]);

}
}

void bc_to_lch_256_16(__m256i* poly, int logn){
for(int offset=(1<<15);offset<(1<<logn);offset+=(1<<(15+1))){
for(int i=offset+(1<<15)-1-16384;i>=offset+(1<<15)-24576;--i)xorEq(poly[i],poly[i+16384]);
for(int i=offset+(1<<15)-1-24576;i>=offset+(1<<15)-28672;--i)xorEq(poly[i],poly[i+16384],poly[i+24576]);
for(int i=offset+(1<<15)-1-28672;i>=offset+(1<<15)-30720;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672]);
for(int i=offset+(1<<15)-1-30720;i>=offset+(1<<15)-31744;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720]);
for(int i=offset+(1<<15)-1-31744;i>=offset+(1<<15)-32256;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744]);
for(int i=offset+(1<<15)-1-32256;i>=offset+(1<<15)-32512;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256]);
for(int i=offset+(1<<15)-1-32512;i>=offset+(1<<15)-32640;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512]);
for(int i=offset+(1<<15)-1-32640;i>=offset+(1<<15)-32704;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640]);
for(int i=offset+(1<<15)-1-32704;i>=offset+(1<<15)-32736;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704]);
for(int i=offset+(1<<15)-1-32736;i>=offset+(1<<15)-32752;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736]);
for(int i=offset+(1<<15)-1-32752;i>=offset+(1<<15)-32760;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752]);
for(int i=offset+(1<<15)-1-32760;i>=offset+(1<<15)-32764;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760]);
for(int i=offset+(1<<15)-1-32764;i>=offset+(1<<15)-32766;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764]);
for(int i=offset+(1<<15)-1-32766;i>=offset+(1<<15)-32767;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766]);
for(int i=offset+(1<<15)-1-32767;i>=offset+(1<<15)-32768;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-0;i>=offset-16384;--i)xorEq(poly[i],poly[i+16384],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-16384;i>=offset-24576;--i)xorEq(poly[i],poly[i+24576],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-24576;i>=offset-28672;--i)xorEq(poly[i],poly[i+28672],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-28672;i>=offset-30720;--i)xorEq(poly[i],poly[i+30720],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-30720;i>=offset-31744;--i)xorEq(poly[i],poly[i+31744],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-31744;i>=offset-32256;--i)xorEq(poly[i],poly[i+32256],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-32256;i>=offset-32512;--i)xorEq(poly[i],poly[i+32512],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-32512;i>=offset-32640;--i)xorEq(poly[i],poly[i+32640],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-32640;i>=offset-32704;--i)xorEq(poly[i],poly[i+32704],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-32704;i>=offset-32736;--i)xorEq(poly[i],poly[i+32736],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-32736;i>=offset-32752;--i)xorEq(poly[i],poly[i+32752],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-32752;i>=offset-32760;--i)xorEq(poly[i],poly[i+32760],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-32760;i>=offset-32764;--i)xorEq(poly[i],poly[i+32764],poly[i+32766],poly[i+32767]);
for(int i=offset-1-32764;i>=offset-32766;--i)xorEq(poly[i],poly[i+32766],poly[i+32767]);
for(int i=offset-1-32766;i>=offset-32767;--i)xorEq(poly[i],poly[i+32767]);

}
for(int offset=(1<<14);offset<(1<<logn);offset+=(1<<(14+1))){
for(int i=offset+(1<<14)-1-12288;i>=offset+(1<<14)-15360;--i)xorEq(poly[i],poly[i+12288]);
for(int i=offset+(1<<14)-1-15360;i>=offset+(1<<14)-16128;--i)xorEq(poly[i],poly[i+12288],poly[i+15360]);
for(int i=offset+(1<<14)-1-16128;i>=offset+(1<<14)-16320;--i)xorEq(poly[i],poly[i+12288],poly[i+15360],poly[i+16128]);
for(int i=offset+(1<<14)-1-16320;i>=offset+(1<<14)-16368;--i)xorEq(poly[i],poly[i+12288],poly[i+15360],poly[i+16128],poly[i+16320]);
for(int i=offset+(1<<14)-1-16368;i>=offset+(1<<14)-16380;--i)xorEq(poly[i],poly[i+12288],poly[i+15360],poly[i+16128],poly[i+16320],poly[i+16368]);
for(int i=offset+(1<<14)-1-16380;i>=offset+(1<<14)-16383;--i)xorEq(poly[i],poly[i+12288],poly[i+15360],poly[i+16128],poly[i+16320],poly[i+16368],poly[i+16380]);
for(int i=offset+(1<<14)-1-16383;i>=offset+(1<<14)-16384;--i)xorEq(poly[i],poly[i+12288],poly[i+15360],poly[i+16128],poly[i+16320],poly[i+16368],poly[i+16380],poly[i+16383]);
for(int i=offset-1-0;i>=offset-12288;--i)xorEq(poly[i],poly[i+12288],poly[i+15360],poly[i+16128],poly[i+16320],poly[i+16368],poly[i+16380],poly[i+16383]);
for(int i=offset-1-12288;i>=offset-15360;--i)xorEq(poly[i],poly[i+15360],poly[i+16128],poly[i+16320],poly[i+16368],poly[i+16380],poly[i+16383]);
for(int i=offset-1-15360;i>=offset-16128;--i)xorEq(poly[i],poly[i+16128],poly[i+16320],poly[i+16368],poly[i+16380],poly[i+16383]);
for(int i=offset-1-16128;i>=offset-16320;--i)xorEq(poly[i],poly[i+16320],poly[i+16368],poly[i+16380],poly[i+16383]);
for(int i=offset-1-16320;i>=offset-16368;--i)xorEq(poly[i],poly[i+16368],poly[i+16380],poly[i+16383]);
for(int i=offset-1-16368;i>=offset-16380;--i)xorEq(poly[i],poly[i+16380],poly[i+16383]);
for(int i=offset-1-16380;i>=offset-16383;--i)xorEq(poly[i],poly[i+16383]);

}
for(int offset=(1<<13);offset<(1<<logn);offset+=(1<<(13+1))){
for(int i=offset+(1<<13)-1-4096;i>=offset+(1<<13)-7680;--i)xorEq(poly[i],poly[i+4096]);
for(int i=offset+(1<<13)-1-7680;i>=offset+(1<<13)-7936;--i)xorEq(poly[i],poly[i+4096],poly[i+7680]);
for(int i=offset+(1<<13)-1-7936;i>=offset+(1<<13)-8160;--i)xorEq(poly[i],poly[i+4096],poly[i+7680],poly[i+7936]);
for(int i=offset+(1<<13)-1-8160;i>=offset+(1<<13)-8176;--i)xorEq(poly[i],poly[i+4096],poly[i+7680],poly[i+7936],poly[i+8160]);
for(int i=offset+(1<<13)-1-8176;i>=offset+(1<<13)-8190;--i)xorEq(poly[i],poly[i+4096],poly[i+7680],poly[i+7936],poly[i+8160],poly[i+8176]);
for(int i=offset+(1<<13)-1-8190;i>=offset+(1<<13)-8191;--i)xorEq(poly[i],poly[i+4096],poly[i+7680],poly[i+7936],poly[i+8160],poly[i+8176],poly[i+8190]);
for(int i=offset+(1<<13)-1-8191;i>=offset+(1<<13)-8192;--i)xorEq(poly[i],poly[i+4096],poly[i+7680],poly[i+7936],poly[i+8160],poly[i+8176],poly[i+8190],poly[i+8191]);
for(int i=offset-1-0;i>=offset-4096;--i)xorEq(poly[i],poly[i+4096],poly[i+7680],poly[i+7936],poly[i+8160],poly[i+8176],poly[i+8190],poly[i+8191]);
for(int i=offset-1-4096;i>=offset-7680;--i)xorEq(poly[i],poly[i+7680],poly[i+7936],poly[i+8160],poly[i+8176],poly[i+8190],poly[i+8191]);
for(int i=offset-1-7680;i>=offset-7936;--i)xorEq(poly[i],poly[i+7936],poly[i+8160],poly[i+8176],poly[i+8190],poly[i+8191]);
for(int i=offset-1-7936;i>=offset-8160;--i)xorEq(poly[i],poly[i+8160],poly[i+8176],poly[i+8190],poly[i+8191]);
for(int i=offset-1-8160;i>=offset-8176;--i)xorEq(poly[i],poly[i+8176],poly[i+8190],poly[i+8191]);
for(int i=offset-1-8176;i>=offset-8190;--i)xorEq(poly[i],poly[i+8190],poly[i+8191]);
for(int i=offset-1-8190;i>=offset-8191;--i)xorEq(poly[i],poly[i+8191]);

}
for(int offset=(1<<12);offset<(1<<logn);offset+=(1<<(12+1))){
for(int i=offset+(1<<12)-1-3840;i>=offset+(1<<12)-4080;--i)xorEq(poly[i],poly[i+3840]);
for(int i=offset+(1<<12)-1-4080;i>=offset+(1<<12)-4095;--i)xorEq(poly[i],poly[i+3840],poly[i+4080]);
for(int i=offset+(1<<12)-1-4095;i>=offset+(1<<12)-4096;--i)xorEq(poly[i],poly[i+3840],poly[i+4080],poly[i+4095]);
for(int i=offset-1-0;i>=offset-3840;--i)xorEq(poly[i],poly[i+3840],poly[i+4080],poly[i+4095]);
for(int i=offset-1-3840;i>=offset-4080;--i)xorEq(poly[i],poly[i+4080],poly[i+4095]);
for(int i=offset-1-4080;i>=offset-4095;--i)xorEq(poly[i],poly[i+4095]);

}
for(int offset=(1<<11);offset<(1<<logn);offset+=(1<<(11+1))){
for(int i=offset+(1<<11)-1-1024;i>=offset+(1<<11)-1536;--i)xorEq(poly[i],poly[i+1024]);
for(int i=offset+(1<<11)-1-1536;i>=offset+(1<<11)-1792;--i)xorEq(poly[i],poly[i+1024],poly[i+1536]);
for(int i=offset+(1<<11)-1-1792;i>=offset+(1<<11)-2040;--i)xorEq(poly[i],poly[i+1024],poly[i+1536],poly[i+1792]);
for(int i=offset+(1<<11)-1-2040;i>=offset+(1<<11)-2044;--i)xorEq(poly[i],poly[i+1024],poly[i+1536],poly[i+1792],poly[i+2040]);
for(int i=offset+(1<<11)-1-2044;i>=offset+(1<<11)-2046;--i)xorEq(poly[i],poly[i+1024],poly[i+1536],poly[i+1792],poly[i+2040],poly[i+2044]);
for(int i=offset+(1<<11)-1-2046;i>=offset+(1<<11)-2047;--i)xorEq(poly[i],poly[i+1024],poly[i+1536],poly[i+1792],poly[i+2040],poly[i+2044],poly[i+2046]);
for(int i=offset+(1<<11)-1-2047;i>=offset+(1<<11)-2048;--i)xorEq(poly[i],poly[i+1024],poly[i+1536],poly[i+1792],poly[i+2040],poly[i+2044],poly[i+2046],poly[i+2047]);
for(int i=offset-1-0;i>=offset-1024;--i)xorEq(poly[i],poly[i+1024],poly[i+1536],poly[i+1792],poly[i+2040],poly[i+2044],poly[i+2046],poly[i+2047]);
for(int i=offset-1-1024;i>=offset-1536;--i)xorEq(poly[i],poly[i+1536],poly[i+1792],poly[i+2040],poly[i+2044],poly[i+2046],poly[i+2047]);
for(int i=offset-1-1536;i>=offset-1792;--i)xorEq(poly[i],poly[i+1792],poly[i+2040],poly[i+2044],poly[i+2046],poly[i+2047]);
for(int i=offset-1-1792;i>=offset-2040;--i)xorEq(poly[i],poly[i+2040],poly[i+2044],poly[i+2046],poly[i+2047]);
for(int i=offset-1-2040;i>=offset-2044;--i)xorEq(poly[i],poly[i+2044],poly[i+2046],poly[i+2047]);
for(int i=offset-1-2044;i>=offset-2046;--i)xorEq(poly[i],poly[i+2046],poly[i+2047]);
for(int i=offset-1-2046;i>=offset-2047;--i)xorEq(poly[i],poly[i+2047]);

}
for(int offset=(1<<10);offset<(1<<logn);offset+=(1<<(10+1))){
for(int i=offset+(1<<10)-1-768;i>=offset+(1<<10)-1020;--i)xorEq(poly[i],poly[i+768]);
for(int i=offset+(1<<10)-1-1020;i>=offset+(1<<10)-1023;--i)xorEq(poly[i],poly[i+768],poly[i+1020]);
for(int i=offset+(1<<10)-1-1023;i>=offset+(1<<10)-1024;--i)xorEq(poly[i],poly[i+768],poly[i+1020],poly[i+1023]);
for(int i=offset-1-0;i>=offset-768;--i)xorEq(poly[i],poly[i+768],poly[i+1020],poly[i+1023]);
for(int i=offset-1-768;i>=offset-1020;--i)xorEq(poly[i],poly[i+1020],poly[i+1023]);
for(int i=offset-1-1020;i>=offset-1023;--i)xorEq(poly[i],poly[i+1023]);

}
for(int offset=(1<<9);offset<(1<<logn);offset+=(1<<(9+1))){
for(int i=offset+(1<<9)-1-256;i>=offset+(1<<9)-510;--i)xorEq(poly[i],poly[i+256]);
for(int i=offset+(1<<9)-1-510;i>=offset+(1<<9)-511;--i)xorEq(poly[i],poly[i+256],poly[i+510]);
for(int i=offset+(1<<9)-1-511;i>=offset+(1<<9)-512;--i)xorEq(poly[i],poly[i+256],poly[i+510],poly[i+511]);
for(int i=offset-1-0;i>=offset-256;--i)xorEq(poly[i],poly[i+256],poly[i+510],poly[i+511]);
for(int i=offset-1-256;i>=offset-510;--i)xorEq(poly[i],poly[i+510],poly[i+511]);
for(int i=offset-1-510;i>=offset-511;--i)xorEq(poly[i],poly[i+511]);

}
for(int offset=(1<<8);offset<(1<<logn);offset+=(1<<(8+1))){
for(int i=offset+(1<<8)-1-255;i>=offset+(1<<8)-256;--i)xorEq(poly[i],poly[i+255]);
for(int i=offset-1-0;i>=offset-255;--i)xorEq(poly[i],poly[i+255]);

}
for(int offset=(1<<7);offset<(1<<logn);offset+=(1<<(7+1))){
for(int i=offset+(1<<7)-1-64;i>=offset+(1<<7)-96;--i)xorEq(poly[i],poly[i+64]);
for(int i=offset+(1<<7)-1-96;i>=offset+(1<<7)-112;--i)xorEq(poly[i],poly[i+64],poly[i+96]);
for(int i=offset+(1<<7)-1-112;i>=offset+(1<<7)-120;--i)xorEq(poly[i],poly[i+64],poly[i+96],poly[i+112]);
for(int i=offset+(1<<7)-1-120;i>=offset+(1<<7)-124;--i)xorEq(poly[i],poly[i+64],poly[i+96],poly[i+112],poly[i+120]);
for(int i=offset+(1<<7)-1-124;i>=offset+(1<<7)-126;--i)xorEq(poly[i],poly[i+64],poly[i+96],poly[i+112],poly[i+120],poly[i+124]);
for(int i=offset+(1<<7)-1-126;i>=offset+(1<<7)-127;--i)xorEq(poly[i],poly[i+64],poly[i+96],poly[i+112],poly[i+120],poly[i+124],poly[i+126]);
for(int i=offset+(1<<7)-1-127;i>=offset+(1<<7)-128;--i)xorEq(poly[i],poly[i+64],poly[i+96],poly[i+112],poly[i+120],poly[i+124],poly[i+126],poly[i+127]);
for(int i=offset-1-0;i>=offset-64;--i)xorEq(poly[i],poly[i+64],poly[i+96],poly[i+112],poly[i+120],poly[i+124],poly[i+126],poly[i+127]);
for(int i=offset-1-64;i>=offset-96;--i)xorEq(poly[i],poly[i+96],poly[i+112],poly[i+120],poly[i+124],poly[i+126],poly[i+127]);
for(int i=offset-1-96;i>=offset-112;--i)xorEq(poly[i],poly[i+112],poly[i+120],poly[i+124],poly[i+126],poly[i+127]);
for(int i=offset-1-112;i>=offset-120;--i)xorEq(poly[i],poly[i+120],poly[i+124],poly[i+126],poly[i+127]);
for(int i=offset-1-120;i>=offset-124;--i)xorEq(poly[i],poly[i+124],poly[i+126],poly[i+127]);
for(int i=offset-1-124;i>=offset-126;--i)xorEq(poly[i],poly[i+126],poly[i+127]);
for(int i=offset-1-126;i>=offset-127;--i)xorEq(poly[i],poly[i+127]);

}
for(int offset=(1<<6);offset<(1<<logn);offset+=(1<<(6+1))){
for(int i=offset+(1<<6)-1-48;i>=offset+(1<<6)-60;--i)xorEq(poly[i],poly[i+48]);
for(int i=offset+(1<<6)-1-60;i>=offset+(1<<6)-63;--i)xorEq(poly[i],poly[i+48],poly[i+60]);
for(int i=offset+(1<<6)-1-63;i>=offset+(1<<6)-64;--i)xorEq(poly[i],poly[i+48],poly[i+60],poly[i+63]);
for(int i=offset-1-0;i>=offset-48;--i)xorEq(poly[i],poly[i+48],poly[i+60],poly[i+63]);
for(int i=offset-1-48;i>=offset-60;--i)xorEq(poly[i],poly[i+60],poly[i+63]);
for(int i=offset-1-60;i>=offset-63;--i)xorEq(poly[i],poly[i+63]);

}
for(int offset=(1<<5);offset<(1<<logn);offset+=(1<<(5+1))){
for(int i=offset+(1<<5)-1-16;i>=offset+(1<<5)-30;--i)xorEq(poly[i],poly[i+16]);
for(int i=offset+(1<<5)-1-30;i>=offset+(1<<5)-31;--i)xorEq(poly[i],poly[i+16],poly[i+30]);
for(int i=offset+(1<<5)-1-31;i>=offset+(1<<5)-32;--i)xorEq(poly[i],poly[i+16],poly[i+30],poly[i+31]);
for(int i=offset-1-0;i>=offset-16;--i)xorEq(poly[i],poly[i+16],poly[i+30],poly[i+31]);
for(int i=offset-1-16;i>=offset-30;--i)xorEq(poly[i],poly[i+30],poly[i+31]);
for(int i=offset-1-30;i>=offset-31;--i)xorEq(poly[i],poly[i+31]);

}
for(int offset=(1<<4);offset<(1<<logn);offset+=(1<<(4+1))){
for(int i=offset+(1<<4)-1-15;i>=offset+(1<<4)-16;--i)xorEq(poly[i],poly[i+15]);
for(int i=offset-1-0;i>=offset-15;--i)xorEq(poly[i],poly[i+15]);

}
for(int offset=(1<<3);offset<(1<<logn);offset+=(1<<(3+1))){
for(int i=offset+(1<<3)-1-4;i>=offset+(1<<3)-6;--i)xorEq(poly[i],poly[i+4]);
for(int i=offset+(1<<3)-1-6;i>=offset+(1<<3)-7;--i)xorEq(poly[i],poly[i+4],poly[i+6]);
for(int i=offset+(1<<3)-1-7;i>=offset+(1<<3)-8;--i)xorEq(poly[i],poly[i+4],poly[i+6],poly[i+7]);
for(int i=offset-1-0;i>=offset-4;--i)xorEq(poly[i],poly[i+4],poly[i+6],poly[i+7]);
for(int i=offset-1-4;i>=offset-6;--i)xorEq(poly[i],poly[i+6],poly[i+7]);
for(int i=offset-1-6;i>=offset-7;--i)xorEq(poly[i],poly[i+7]);

}
for(int offset=(1<<2);offset<(1<<logn);offset+=(1<<(2+1))){
for(int i=offset+(1<<2)-1-3;i>=offset+(1<<2)-4;--i)xorEq(poly[i],poly[i+3]);
for(int i=offset-1-0;i>=offset-3;--i)xorEq(poly[i],poly[i+3]);

}
for(int offset=(1<<1);offset<(1<<logn);offset+=(1<<(1+1))){
for(int i=offset+(1<<1)-1-1;i>=offset+(1<<1)-2;--i)xorEq(poly[i],poly[i+1]);
for(int i=offset-1-0;i>=offset-1;--i)xorEq(poly[i],poly[i+1]);

}
}
}
#endif