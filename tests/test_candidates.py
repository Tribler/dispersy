# disable C0111, Missing docstring.  the auto generated tests do not conform to this rule.
# pylint: disable=C0111

# disable C0321, More than one statement on a single line.  the auto generated tests do not conform to this rule.
# pylint: disable=C0321

# disable C0301, Line too long.  the auto generated tests do not conform to this rule.
# pylint: disable=C0301

import logging
logger = logging.getLogger(__name__)

from fractions import gcd
from itertools import combinations, islice
from time import time

from ..candidate import CANDIDATE_ELIGIBLE_DELAY
from ..tool.tracker import TrackerCommunity
from .debugcommunity.community import DebugCommunity
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


def print_unittest_combinations():
    """
    Prints combinations of unit tests.
    """
    print "    def test_no_candidates(self): return self.check_candidates([])"
    flags = "twresi"
    options = []
    for length in xrange(len(flags)):
        for string in combinations(flags, length):
            s_func = "_" + "".join(string) if string else ""
            s_args = '"%s"' % "".join(string)
            s_opt = "".join(string)
            options.append(s_opt)

            print "    def test_one%s_candidate(self): return self.check_candidates([%s])" % \
                (s_func, s_args)
            print "    def test_two%s_candidates(self): return self.check_candidates([%s, %s])" % \
                (s_func, s_args, s_args)
            print "    def test_many%s_candidates(self): return self.check_candidates([%s] * 22)" % \
                (s_func, s_args)

    for length in xrange(1, len(options) + 1):
        print "    def test_mixed_%d_candidates(self): return self.check_candidates(%s)" % \
            (length, options[:length])


class NoBootstrapDebugCommunity(DebugCommunity):

    def _iter_bootstrap(self, once=False):
        while True:
            yield None

            if once:
                break


class TestCandidates(DispersyTestFunc):
    """
    Tests candidate interface.

    This unit tests covers the methods:
    - dispersy_yield_candidates
    - dispersy_yield_verified_candidates
    - dispersy_get_introduce_candidate
    - dispersy_get_walk_candidate

    Most tests are performed with check_candidates, this method takes ALL_FLAGS, list were every entry is a string.  The
    following characters can be put in the string to enable a candidate property:
    - t: SELF knows the candidate is tunnelled
    - w: SELF has walked towards the candidate (but has not yet received a response)
    - r: SELF has received a walk response from the candidate
    - e: CANDIDATE_ELIGIBLE_DELAY seconds ago SELF performed a successful walk to candidate
    - s: SELF has received an incoming walk from the candidate
    - i: SELF has been introduced to the candidate

    Note that many variations of flags exist, multiple variations are generated using print_unittest_combinations.
    """

    def test_no_candidates(self): return self.check_candidates([])
    def test_one_candidate(self): return self.check_candidates([""])
    def test_two_candidates(self): return self.check_candidates(["", ""])
    def test_many_candidates(self): return self.check_candidates([""] * 22)
    def test_one_t_candidate(self): return self.check_candidates(["t"])
    def test_two_t_candidates(self): return self.check_candidates(["t", "t"])
    def test_many_t_candidates(self): return self.check_candidates(["t"] * 22)
    def test_one_w_candidate(self): return self.check_candidates(["w"])
    def test_two_w_candidates(self): return self.check_candidates(["w", "w"])
    def test_many_w_candidates(self): return self.check_candidates(["w"] * 22)
    def test_one_r_candidate(self): return self.check_candidates(["r"])
    def test_two_r_candidates(self): return self.check_candidates(["r", "r"])
    def test_many_r_candidates(self): return self.check_candidates(["r"] * 22)
    def test_one_e_candidate(self): return self.check_candidates(["e"])
    def test_two_e_candidates(self): return self.check_candidates(["e", "e"])
    def test_many_e_candidates(self): return self.check_candidates(["e"] * 22)
    def test_one_s_candidate(self): return self.check_candidates(["s"])
    def test_two_s_candidates(self): return self.check_candidates(["s", "s"])
    def test_many_s_candidates(self): return self.check_candidates(["s"] * 22)
    def test_one_i_candidate(self): return self.check_candidates(["i"])
    def test_two_i_candidates(self): return self.check_candidates(["i", "i"])
    def test_many_i_candidates(self): return self.check_candidates(["i"] * 22)
    def test_one_tw_candidate(self): return self.check_candidates(["tw"])
    def test_two_tw_candidates(self): return self.check_candidates(["tw", "tw"])
    def test_many_tw_candidates(self): return self.check_candidates(["tw"] * 22)
    def test_one_tr_candidate(self): return self.check_candidates(["tr"])
    def test_two_tr_candidates(self): return self.check_candidates(["tr", "tr"])
    def test_many_tr_candidates(self): return self.check_candidates(["tr"] * 22)
    def test_one_te_candidate(self): return self.check_candidates(["te"])
    def test_two_te_candidates(self): return self.check_candidates(["te", "te"])
    def test_many_te_candidates(self): return self.check_candidates(["te"] * 22)
    def test_one_ts_candidate(self): return self.check_candidates(["ts"])
    def test_two_ts_candidates(self): return self.check_candidates(["ts", "ts"])
    def test_many_ts_candidates(self): return self.check_candidates(["ts"] * 22)
    def test_one_ti_candidate(self): return self.check_candidates(["ti"])
    def test_two_ti_candidates(self): return self.check_candidates(["ti", "ti"])
    def test_many_ti_candidates(self): return self.check_candidates(["ti"] * 22)
    def test_one_wr_candidate(self): return self.check_candidates(["wr"])
    def test_two_wr_candidates(self): return self.check_candidates(["wr", "wr"])
    def test_many_wr_candidates(self): return self.check_candidates(["wr"] * 22)
    def test_one_we_candidate(self): return self.check_candidates(["we"])
    def test_two_we_candidates(self): return self.check_candidates(["we", "we"])
    def test_many_we_candidates(self): return self.check_candidates(["we"] * 22)
    def test_one_ws_candidate(self): return self.check_candidates(["ws"])
    def test_two_ws_candidates(self): return self.check_candidates(["ws", "ws"])
    def test_many_ws_candidates(self): return self.check_candidates(["ws"] * 22)
    def test_one_wi_candidate(self): return self.check_candidates(["wi"])
    def test_two_wi_candidates(self): return self.check_candidates(["wi", "wi"])
    def test_many_wi_candidates(self): return self.check_candidates(["wi"] * 22)
    def test_one_re_candidate(self): return self.check_candidates(["re"])
    def test_two_re_candidates(self): return self.check_candidates(["re", "re"])
    def test_many_re_candidates(self): return self.check_candidates(["re"] * 22)
    def test_one_rs_candidate(self): return self.check_candidates(["rs"])
    def test_two_rs_candidates(self): return self.check_candidates(["rs", "rs"])
    def test_many_rs_candidates(self): return self.check_candidates(["rs"] * 22)
    def test_one_ri_candidate(self): return self.check_candidates(["ri"])
    def test_two_ri_candidates(self): return self.check_candidates(["ri", "ri"])
    def test_many_ri_candidates(self): return self.check_candidates(["ri"] * 22)
    def test_one_es_candidate(self): return self.check_candidates(["es"])
    def test_two_es_candidates(self): return self.check_candidates(["es", "es"])
    def test_many_es_candidates(self): return self.check_candidates(["es"] * 22)
    def test_one_ei_candidate(self): return self.check_candidates(["ei"])
    def test_two_ei_candidates(self): return self.check_candidates(["ei", "ei"])
    def test_many_ei_candidates(self): return self.check_candidates(["ei"] * 22)
    def test_one_si_candidate(self): return self.check_candidates(["si"])
    def test_two_si_candidates(self): return self.check_candidates(["si", "si"])
    def test_many_si_candidates(self): return self.check_candidates(["si"] * 22)
    def test_one_twr_candidate(self): return self.check_candidates(["twr"])
    def test_two_twr_candidates(self): return self.check_candidates(["twr", "twr"])
    def test_many_twr_candidates(self): return self.check_candidates(["twr"] * 22)
    def test_one_twe_candidate(self): return self.check_candidates(["twe"])
    def test_two_twe_candidates(self): return self.check_candidates(["twe", "twe"])
    def test_many_twe_candidates(self): return self.check_candidates(["twe"] * 22)
    def test_one_tws_candidate(self): return self.check_candidates(["tws"])
    def test_two_tws_candidates(self): return self.check_candidates(["tws", "tws"])
    def test_many_tws_candidates(self): return self.check_candidates(["tws"] * 22)
    def test_one_twi_candidate(self): return self.check_candidates(["twi"])
    def test_two_twi_candidates(self): return self.check_candidates(["twi", "twi"])
    def test_many_twi_candidates(self): return self.check_candidates(["twi"] * 22)
    def test_one_tre_candidate(self): return self.check_candidates(["tre"])
    def test_two_tre_candidates(self): return self.check_candidates(["tre", "tre"])
    def test_many_tre_candidates(self): return self.check_candidates(["tre"] * 22)
    def test_one_trs_candidate(self): return self.check_candidates(["trs"])
    def test_two_trs_candidates(self): return self.check_candidates(["trs", "trs"])
    def test_many_trs_candidates(self): return self.check_candidates(["trs"] * 22)
    def test_one_tri_candidate(self): return self.check_candidates(["tri"])
    def test_two_tri_candidates(self): return self.check_candidates(["tri", "tri"])
    def test_many_tri_candidates(self): return self.check_candidates(["tri"] * 22)
    def test_one_tes_candidate(self): return self.check_candidates(["tes"])
    def test_two_tes_candidates(self): return self.check_candidates(["tes", "tes"])
    def test_many_tes_candidates(self): return self.check_candidates(["tes"] * 22)
    def test_one_tei_candidate(self): return self.check_candidates(["tei"])
    def test_two_tei_candidates(self): return self.check_candidates(["tei", "tei"])
    def test_many_tei_candidates(self): return self.check_candidates(["tei"] * 22)
    def test_one_tsi_candidate(self): return self.check_candidates(["tsi"])
    def test_two_tsi_candidates(self): return self.check_candidates(["tsi", "tsi"])
    def test_many_tsi_candidates(self): return self.check_candidates(["tsi"] * 22)
    def test_one_wre_candidate(self): return self.check_candidates(["wre"])
    def test_two_wre_candidates(self): return self.check_candidates(["wre", "wre"])
    def test_many_wre_candidates(self): return self.check_candidates(["wre"] * 22)
    def test_one_wrs_candidate(self): return self.check_candidates(["wrs"])
    def test_two_wrs_candidates(self): return self.check_candidates(["wrs", "wrs"])
    def test_many_wrs_candidates(self): return self.check_candidates(["wrs"] * 22)
    def test_one_wri_candidate(self): return self.check_candidates(["wri"])
    def test_two_wri_candidates(self): return self.check_candidates(["wri", "wri"])
    def test_many_wri_candidates(self): return self.check_candidates(["wri"] * 22)
    def test_one_wes_candidate(self): return self.check_candidates(["wes"])
    def test_two_wes_candidates(self): return self.check_candidates(["wes", "wes"])
    def test_many_wes_candidates(self): return self.check_candidates(["wes"] * 22)
    def test_one_wei_candidate(self): return self.check_candidates(["wei"])
    def test_two_wei_candidates(self): return self.check_candidates(["wei", "wei"])
    def test_many_wei_candidates(self): return self.check_candidates(["wei"] * 22)
    def test_one_wsi_candidate(self): return self.check_candidates(["wsi"])
    def test_two_wsi_candidates(self): return self.check_candidates(["wsi", "wsi"])
    def test_many_wsi_candidates(self): return self.check_candidates(["wsi"] * 22)
    def test_one_res_candidate(self): return self.check_candidates(["res"])
    def test_two_res_candidates(self): return self.check_candidates(["res", "res"])
    def test_many_res_candidates(self): return self.check_candidates(["res"] * 22)
    def test_one_rei_candidate(self): return self.check_candidates(["rei"])
    def test_two_rei_candidates(self): return self.check_candidates(["rei", "rei"])
    def test_many_rei_candidates(self): return self.check_candidates(["rei"] * 22)
    def test_one_rsi_candidate(self): return self.check_candidates(["rsi"])
    def test_two_rsi_candidates(self): return self.check_candidates(["rsi", "rsi"])
    def test_many_rsi_candidates(self): return self.check_candidates(["rsi"] * 22)
    def test_one_esi_candidate(self): return self.check_candidates(["esi"])
    def test_two_esi_candidates(self): return self.check_candidates(["esi", "esi"])
    def test_many_esi_candidates(self): return self.check_candidates(["esi"] * 22)
    def test_one_twre_candidate(self): return self.check_candidates(["twre"])
    def test_two_twre_candidates(self): return self.check_candidates(["twre", "twre"])
    def test_many_twre_candidates(self): return self.check_candidates(["twre"] * 22)
    def test_one_twrs_candidate(self): return self.check_candidates(["twrs"])
    def test_two_twrs_candidates(self): return self.check_candidates(["twrs", "twrs"])
    def test_many_twrs_candidates(self): return self.check_candidates(["twrs"] * 22)
    def test_one_twri_candidate(self): return self.check_candidates(["twri"])
    def test_two_twri_candidates(self): return self.check_candidates(["twri", "twri"])
    def test_many_twri_candidates(self): return self.check_candidates(["twri"] * 22)
    def test_one_twes_candidate(self): return self.check_candidates(["twes"])
    def test_two_twes_candidates(self): return self.check_candidates(["twes", "twes"])
    def test_many_twes_candidates(self): return self.check_candidates(["twes"] * 22)
    def test_one_twei_candidate(self): return self.check_candidates(["twei"])
    def test_two_twei_candidates(self): return self.check_candidates(["twei", "twei"])
    def test_many_twei_candidates(self): return self.check_candidates(["twei"] * 22)
    def test_one_twsi_candidate(self): return self.check_candidates(["twsi"])
    def test_two_twsi_candidates(self): return self.check_candidates(["twsi", "twsi"])
    def test_many_twsi_candidates(self): return self.check_candidates(["twsi"] * 22)
    def test_one_tres_candidate(self): return self.check_candidates(["tres"])
    def test_two_tres_candidates(self): return self.check_candidates(["tres", "tres"])
    def test_many_tres_candidates(self): return self.check_candidates(["tres"] * 22)
    def test_one_trei_candidate(self): return self.check_candidates(["trei"])
    def test_two_trei_candidates(self): return self.check_candidates(["trei", "trei"])
    def test_many_trei_candidates(self): return self.check_candidates(["trei"] * 22)
    def test_one_trsi_candidate(self): return self.check_candidates(["trsi"])
    def test_two_trsi_candidates(self): return self.check_candidates(["trsi", "trsi"])
    def test_many_trsi_candidates(self): return self.check_candidates(["trsi"] * 22)
    def test_one_tesi_candidate(self): return self.check_candidates(["tesi"])
    def test_two_tesi_candidates(self): return self.check_candidates(["tesi", "tesi"])
    def test_many_tesi_candidates(self): return self.check_candidates(["tesi"] * 22)
    def test_one_wres_candidate(self): return self.check_candidates(["wres"])
    def test_two_wres_candidates(self): return self.check_candidates(["wres", "wres"])
    def test_many_wres_candidates(self): return self.check_candidates(["wres"] * 22)
    def test_one_wrei_candidate(self): return self.check_candidates(["wrei"])
    def test_two_wrei_candidates(self): return self.check_candidates(["wrei", "wrei"])
    def test_many_wrei_candidates(self): return self.check_candidates(["wrei"] * 22)
    def test_one_wrsi_candidate(self): return self.check_candidates(["wrsi"])
    def test_two_wrsi_candidates(self): return self.check_candidates(["wrsi", "wrsi"])
    def test_many_wrsi_candidates(self): return self.check_candidates(["wrsi"] * 22)
    def test_one_wesi_candidate(self): return self.check_candidates(["wesi"])
    def test_two_wesi_candidates(self): return self.check_candidates(["wesi", "wesi"])
    def test_many_wesi_candidates(self): return self.check_candidates(["wesi"] * 22)
    def test_one_resi_candidate(self): return self.check_candidates(["resi"])
    def test_two_resi_candidates(self): return self.check_candidates(["resi", "resi"])
    def test_many_resi_candidates(self): return self.check_candidates(["resi"] * 22)
    def test_one_twres_candidate(self): return self.check_candidates(["twres"])
    def test_two_twres_candidates(self): return self.check_candidates(["twres", "twres"])
    def test_many_twres_candidates(self): return self.check_candidates(["twres"] * 22)
    def test_one_twrei_candidate(self): return self.check_candidates(["twrei"])
    def test_two_twrei_candidates(self): return self.check_candidates(["twrei", "twrei"])
    def test_many_twrei_candidates(self): return self.check_candidates(["twrei"] * 22)
    def test_one_twrsi_candidate(self): return self.check_candidates(["twrsi"])
    def test_two_twrsi_candidates(self): return self.check_candidates(["twrsi", "twrsi"])
    def test_many_twrsi_candidates(self): return self.check_candidates(["twrsi"] * 22)
    def test_one_twesi_candidate(self): return self.check_candidates(["twesi"])
    def test_two_twesi_candidates(self): return self.check_candidates(["twesi", "twesi"])
    def test_many_twesi_candidates(self): return self.check_candidates(["twesi"] * 22)
    def test_one_tresi_candidate(self): return self.check_candidates(["tresi"])
    def test_two_tresi_candidates(self): return self.check_candidates(["tresi", "tresi"])
    def test_many_tresi_candidates(self): return self.check_candidates(["tresi"] * 22)
    def test_one_wresi_candidate(self): return self.check_candidates(["wresi"])
    def test_two_wresi_candidates(self): return self.check_candidates(["wresi", "wresi"])
    def test_many_wresi_candidates(self): return self.check_candidates(["wresi"] * 22)
    def test_mixed_1_candidates(self): return self.check_candidates([''])
    def test_mixed_2_candidates(self): return self.check_candidates(['', 't'])
    def test_mixed_3_candidates(self): return self.check_candidates(['', 't', 'w'])
    def test_mixed_4_candidates(self): return self.check_candidates(['', 't', 'w', 'r'])
    def test_mixed_5_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e'])
    def test_mixed_6_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's'])
    def test_mixed_7_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i'])
    def test_mixed_8_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw'])
    def test_mixed_9_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr'])
    def test_mixed_10_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te'])
    def test_mixed_11_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts'])
    def test_mixed_12_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti'])
    def test_mixed_13_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr'])
    def test_mixed_14_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we'])
    def test_mixed_15_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws'])
    def test_mixed_16_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi'])
    def test_mixed_17_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're'])
    def test_mixed_18_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs'])
    def test_mixed_19_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri'])
    def test_mixed_20_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es'])
    def test_mixed_21_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei'])
    def test_mixed_22_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si'])
    def test_mixed_23_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr'])
    def test_mixed_24_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe'])
    def test_mixed_25_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws'])
    def test_mixed_26_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi'])
    def test_mixed_27_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre'])
    def test_mixed_28_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs'])
    def test_mixed_29_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri'])
    def test_mixed_30_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes'])
    def test_mixed_31_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei'])
    def test_mixed_32_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi'])
    def test_mixed_33_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre'])
    def test_mixed_34_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs'])
    def test_mixed_35_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri'])
    def test_mixed_36_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes'])
    def test_mixed_37_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei'])
    def test_mixed_38_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi'])
    def test_mixed_39_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res'])
    def test_mixed_40_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei'])
    def test_mixed_41_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi'])
    def test_mixed_42_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi'])
    def test_mixed_43_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre'])
    def test_mixed_44_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs'])
    def test_mixed_45_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri'])
    def test_mixed_46_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes'])
    def test_mixed_47_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei'])
    def test_mixed_48_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi'])
    def test_mixed_49_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres'])
    def test_mixed_50_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei'])
    def test_mixed_51_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi'])
    def test_mixed_52_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi'])
    def test_mixed_53_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres'])
    def test_mixed_54_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei'])
    def test_mixed_55_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei', 'wrsi'])
    def test_mixed_56_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei', 'wrsi', 'wesi'])
    def test_mixed_57_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei', 'wrsi', 'wesi', 'resi'])
    def test_mixed_58_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei', 'wrsi', 'wesi', 'resi', 'twres'])
    def test_mixed_59_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei', 'wrsi', 'wesi', 'resi', 'twres', 'twrei'])
    def test_mixed_60_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei', 'wrsi', 'wesi', 'resi', 'twres', 'twrei', 'twrsi'])
    def test_mixed_61_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei', 'wrsi', 'wesi', 'resi', 'twres', 'twrei', 'twrsi', 'twesi'])
    def test_mixed_62_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei', 'wrsi', 'wesi', 'resi', 'twres', 'twrei', 'twrsi', 'twesi', 'tresi'])
    def test_mixed_63_candidates(self): return self.check_candidates(['', 't', 'w', 'r', 'e', 's', 'i', 'tw', 'tr', 'te', 'ts', 'ti', 'wr', 'we', 'ws', 'wi', 're', 'rs', 'ri', 'es', 'ei', 'si', 'twr', 'twe', 'tws', 'twi', 'tre', 'trs', 'tri', 'tes', 'tei', 'tsi', 'wre', 'wrs', 'wri', 'wes', 'wei', 'wsi', 'res', 'rei', 'rsi', 'esi', 'twre', 'twrs', 'twri', 'twes', 'twei', 'twsi', 'tres', 'trei', 'trsi', 'tesi', 'wres', 'wrei', 'wrsi', 'wesi', 'resi', 'twres', 'twrei', 'twrsi', 'twesi', 'tresi', 'wresi'])

    @staticmethod
    def create_candidates(community, all_flags):
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)
        def generator():
            for port, flags in enumerate(all_flags, 1):
                address = ("127.0.0.1", port)
                tunnel = "t" in flags
                yield community.create_candidate(address, tunnel, address, address, u"unknown")
        with community.dispersy.database:
            return list(generator())

    @staticmethod
    def set_timestamps(candidates, all_flags):
        assert isinstance(candidates, list)
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)
        now = time()
        for flags, candidate in zip(all_flags, candidates):
            if "w" in flags:
                # SELF has performed an outgoing walk to CANDIDATE
                candidate.walk(now, 10.0)
            if "r" in flags:
                # SELF has received an incoming walk response from CANDIDATE
                candidate.walk_response()
            if "e" in flags:
                # CANDIDATE_ELIGIBLE_DELAY seconds ago SELF performed a successful walk to CANDIDATE
                candidate.walk(now - CANDIDATE_ELIGIBLE_DELAY, 10.0)
                candidate.walk_response()
            if "s" in flags:
                # SELF has received an incoming walk request from CANDIDATE
                candidate.stumble(now)
            if "i" in flags:
                # SELF has received an incoming walk response which introduced CANDIDATE
                candidate.intro(now)

        return now

    @staticmethod
    def select_candidates(candidates, all_flags):
        def filter_func(flags):
            """
            Returns True when the flags correspond with a Candidate that should be returned by
            dispersy_yield_candidates.
            """
            return ("s" in flags or
                    "e" in flags or
                    "i" in flags or
                    ("w" in flags and "r" in flags))

        return [candidate for flags, candidate in zip(all_flags, candidates) if filter_func(flags)]

    @staticmethod
    def select_verified_candidates(candidates, all_flags):
        def filter_func(flags):
            """
            Returns True when the flags correspond with a Candidate that should be returned by
            dispersy_yield_verified_candidates.
            """
            return ("s" in flags or
                    "e" in flags or
                    ("w" in flags and "r" in flags))

        return [candidate for flags, candidate in zip(all_flags, candidates) if filter_func(flags)]

    @staticmethod
    def select_walk_candidates(candidates, all_flags):
        def filter_func(flags):
            """
            Returns True when the flags correspond with a Candidate that should be returned by
            dispersy_get_walk_candidate.
            """
            if "e" in flags:
                # the candidate has 'eligible' flag, i.e. it is known and we walked to it at least
                # CANDIDATE_ELIGIBLE_DELAY seconds ago
                return True

            if "s" in flags and not "w" in flags:
                # the candidate has the 'stumble' but not the 'walk' flag, i.e. it is known but we have not recently
                # walked towards it
                return True

            if "i" in flags and not "w" in flags:
                # the candidate has the 'introduce' but not the 'walk' flag, i.e. it is known but we have not recently
                # walked towards it
                return True

            return False

        return [candidate for flags, candidate in zip(all_flags, candidates) if filter_func(flags)]

    @staticmethod
    def select_introduce_candidates(candidates, all_flags, exclude_candidate=None):
        def filter_func(flags, candidate):
            """
            Returns True when the flags correspond with a Candidate that should be returned by
            dispersy_get_introduce_candidate.
            """
            if exclude_candidate and exclude_candidate == candidate:
                return

            if exclude_candidate and not exclude_candidate.tunnel and candidate.tunnel:
                return

            if "s" in flags:
                return "s"

            if ("e" in flags or
                ("w" in flags and "r" in flags)):
                return "w"

        # introduce candidates are chosen from two pools, W and S.  With both pools chosen equally often, regardless of
        # the size of the pools.  Hence, candidates in smaller pools will be represented more often in the result.

        walk = [candidate
                for flags, candidate
                in zip(all_flags, candidates)
                if filter_func(flags, candidate) == "w"]

        stumble = [candidate
                   for flags, candidate
                   in zip(all_flags, candidates)
                   if filter_func(flags, candidate) == "s"]

        if walk and stumble:
            factor = gcd(len(stumble), len(walk))
            pool = (walk * (len(stumble) / factor)) + (stumble * (len(walk) / factor))
        else:
            pool = walk + stumble

        return sorted(pool)

    @call_on_dispersy_thread
    def check_candidates(self, all_flags):
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)

        def compare(selection, actual):
            selection = ["%s:%d" % c.sock_addr if c else None for c in selection]
            actual = ["%s:%d" % c.sock_addr if c else None for c in actual]
            try:
                self.assertEquals(set(selection), set(actual))
            except:
                print "FLAGS ", all_flags
                print "SELECT", selection
                print "ACTUAL", actual
                raise

        # MAX_CALLS determines the number of times that an interface method is called, it should be more than zero and
        # the length of ALL_FLAGS to ensure the tests can succeed
        max_calls = max(10, len(all_flags) * 2)
        # MAX_ITERATIONS determined the number of iterations that an iterator interface method is used, it can be very
        # large since the iterators should end way before this number is reached
        max_iterations = 666

        assert isinstance(max_calls, int)
        assert isinstance(max_iterations, int)
        assert len(all_flags) < max_iterations
        community = NoBootstrapDebugCommunity.create_community(self._dispersy, self._my_member)
        candidates = self.create_candidates(community, all_flags)

        # yield_candidates
        self.set_timestamps(candidates, all_flags)
        selection = self.select_candidates(candidates, all_flags)
        actual_list = [islice(community.dispersy_yield_candidates(), max_iterations) for _ in xrange(max_calls)]
        logger.debug("A] candidates:  %s", [str(candidate) for candidate in candidates])
        logger.debug("A] selection:   %s", [str(candidate) for candidate in selection])
        logger.debug("A] actual_list: %s", [str(candidate) for candidate in actual_list])
        for actual in actual_list:
            compare(selection, actual)

        # yield_verified_candidates
        self.set_timestamps(candidates, all_flags)
        selection = self.select_verified_candidates(candidates, all_flags)
        actual_list = [islice(community.dispersy_yield_verified_candidates(), max_iterations) for _ in xrange(max_calls)]
        logger.debug("B] candidates:  %s", [str(candidate) for candidate in candidates])
        logger.debug("B] selection:   %s", [str(candidate) for candidate in selection])
        logger.debug("B] actual_list: %s", [str(candidate) for candidate in actual_list])
        for actual in actual_list:
            compare(selection, actual)

        # get_introduce_candidate (no exclusion)
        self.set_timestamps(candidates, all_flags)
        selection = self.select_introduce_candidates(candidates, all_flags) or [None]
        actual = [community.dispersy_get_introduce_candidate() for _ in xrange(max_calls)]
        logger.debug("C] candidates:  %s", [str(candidate) for candidate in candidates])
        logger.debug("C] selection:   %s", [str(candidate) for candidate in selection])
        logger.debug("C] actual_list: %s", [str(candidate) for candidate in actual_list])
        compare(selection, actual)

        # get_introduce_candidate (with exclusion)
        self.set_timestamps(candidates, all_flags)
        for candidate in candidates:
            selection = self.select_introduce_candidates(candidates, all_flags, candidate) or [None]
            actual = [community.dispersy_get_introduce_candidate(candidate) for _ in xrange(max_calls)]
            logger.debug("D] exclude:     %s", str(candidate))
            logger.debug("D] candidates:  %s", [str(candidate) for candidate in candidates])
            logger.debug("D] selection:   %s", [str(candidate) for candidate in selection])
            logger.debug("D] actual_list: %s", [str(candidate) for candidate in actual])
            compare(selection, actual)

        # get_walk_candidate
        # Note that we must perform the CANDIDATE.WALK to ensure this candidate is not iterated again.  Because of this,
        # this test must be done last.
        self.set_timestamps(candidates, all_flags)
        selection = self.select_walk_candidates(candidates, all_flags)
        logger.debug("E] candidates:  %s", [str(candidate) for candidate in candidates])
        logger.debug("E] selection:   %s", [str(candidate) for candidate in selection])
        for _ in xrange(len(selection)):
            candidate = community.dispersy_get_walk_candidate()
            self.assertNotEquals(candidate, None)
            self.assertIn("%s:%d" % candidate.sock_addr, ["%s:%d" % c.sock_addr for c in selection])
            candidate.walk(time(), 10.5)
        for _ in xrange(5):
            candidate = community.dispersy_get_walk_candidate()
            self.assertEquals(candidate, None)

    @call_on_dispersy_thread
    def test_get_introduce_candidate(self, community_create_method=DebugCommunity.create_community):
        community = community_create_method(self._dispersy, self._my_member)
        candidates = self.create_candidates(community, [""] * 5)
        expected = [None, ("127.0.0.1", 1), ("127.0.0.1", 2), ("127.0.0.1", 3), ("127.0.0.1", 4)]
        now = time()
        got = []
        for candidate in candidates:
            candidate.stumble(now)
            introduce = community.dispersy_get_introduce_candidate(candidate)
            got.append(introduce.sock_addr if introduce else None)
        self.assertEquals(expected, got)

        return community, candidates

    @call_on_dispersy_thread
    def test_tracker_get_introduce_candidate(self, community_create_method=TrackerCommunity.create_community):
        community, candidates = self.test_get_introduce_candidate(community_create_method)

        # trackers should not prefer either stumbled or walked candidates, i.e. it should not return
        # candidate 1 more than once/in the wrong position
        now = time()
        candidates[0].walk(now, 10.5)
        candidates[0].walk_response()
        expected = [("127.0.0.1", 5), ("127.0.0.1", 1), ("127.0.0.1", 2), ("127.0.0.1", 3), ("127.0.0.1", 4)]
        got = []
        for candidate in candidates:
            candidate.stumble(now)
            introduce = community.dispersy_get_introduce_candidate(candidate)
            got.append(introduce.sock_addr if introduce else None)
        self.assertEquals(expected, got)

    @call_on_dispersy_thread
    def test_introduction_probabilities(self):
        c = DebugCommunity.create_community(self._dispersy, self._my_member)

        candidates = []
        for i in range(2):
            address = ("127.0.0.1", i + 1)
            candidate = c.create_candidate(address, False, address, address, u"unknown")
            candidates.append(candidate)

        # mark 1 candidate as walk, 1 as stumble
        now = time()
        candidates[0].walk(now, 10.5)
        candidates[0].walk_response()
        candidates[1].stumble(now)

        # fetch candidates
        returned_walked_candidate = 0
        expected_walked_range = range(4500, 5500)
        for i in xrange(10000):
            candidate = c.dispersy_get_introduce_candidate()
            returned_walked_candidate += 1 if candidate.sock_addr[1] == 1 else 0

        assert returned_walked_candidate in expected_walked_range

    @call_on_dispersy_thread
    def test_walk_probabilities(self):
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        candidates = []
        for i in range(3):
            address = ("127.0.0.1", i + 1)
            candidate = community.create_candidate(address, False, address, address, u"unknown")
            candidates.append(candidate)

        # mark 1 candidate as walk, 1 as stumble
        now = time()
        candidates[0].walk(now - CANDIDATE_ELIGIBLE_DELAY, 10.5)
        candidates[0].walk_response()
        candidates[1].stumble(now)
        candidates[2].intro(now)

        # fetch candidates
        returned_walked_candidate = 0
        expected_walked_range = range(4497, 5475)
        returned_stumble_candidate = 0
        expected_stumble_range = range(1975, 2975)
        returned_intro_candidate = 0
        expected_intro_range = range(1975, 2975)
        for i in xrange(10000):
            candidate = community.dispersy_get_walk_candidate()

            returned_walked_candidate += 1 if candidate.sock_addr[1] == 1 else 0
            returned_stumble_candidate += 1 if candidate.sock_addr[1] == 2 else 0
            returned_intro_candidate += 1 if candidate.sock_addr[1] == 3 else 0

        assert returned_walked_candidate in expected_walked_range, returned_walked_candidate
        assert returned_stumble_candidate in expected_stumble_range, returned_stumble_candidate
        assert returned_intro_candidate in expected_intro_range, returned_intro_candidate

    @call_on_dispersy_thread
    def test_merge_candidates(self):
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # let's make a list of all possible combinations which should be merged into one candidate
        candidates = []
        candidates.append(community.create_candidate(("1.1.1.1", 1), False, ("192.168.0.1", 1), ("1.1.1.1", 1), u"unknown"))
        candidates.append(community.create_candidate(("1.1.1.1", 2), False, ("192.168.0.1", 1), ("1.1.1.1", 2), u"symmetric-NAT"))
        candidates.append(community.create_candidate(("1.1.1.1", 3), False, ("192.168.0.1", 1), ("1.1.1.1", 3), u"symmetric-NAT"))
        candidates.append(community.create_candidate(("1.1.1.1", 4), False, ("192.168.0.1", 1), ("1.1.1.1", 4), u"unknown"))

        community.filter_duplicate_candidate(candidates[0])

        expected = [candidates[0].wan_address]

        got = []
        for candidate in community._candidates.itervalues():
            got.append(candidate.wan_address)

        self.assertEquals(expected, got)
