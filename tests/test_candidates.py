# disable C0111, Missing docstring.  the auto generated tests do not conform to this rule.
# pylint: disable=C0111

# disable C0321, More than one statement on a single line.  the auto generated tests do not conform to this rule.
# pylint: disable=C0321

# disable C0301, Line too long.  the auto generated tests do not conform to this rule.
# pylint: disable=C0301

from itertools import combinations, islice
from time import time

from ..candidate import CANDIDATE_ELIGIBLE_DELAY, CANDIDATE_LIFETIME
from ..tracker.community import TrackerCommunity
from ..util import blocking_call_on_reactor_thread
from .debugcommunity.community import DebugCommunity
from .dispersytestclass import DispersyTestFunc


def print_unittest_combinations():
    """
    Prints combinations of unit tests.
    """
    print "    def test_no_candidates(self): return self.check_candidates([])"
    flags = "twresid"
    options = []
    for length in xrange(len(flags)):
        for string in combinations(flags, length):
            # receiving a reply without sending a request cannot happen, don't test
            if 'r' in string and not 'w' in string:
                continue
            # being eligable overwrites walked and received response
            if 'e' in string and ('w' in string or 'r' in string):
                continue

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

if __name__ == "__main__":
    print_unittest_combinations()


class NoBootstrapDebugCommunity(DebugCommunity):

    @property
    def dispersy_enable_candidate_walker(self):
        return False


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
    - d: SELF has been discovered by the discovery community

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
    def test_one_e_candidate(self): return self.check_candidates(["e"])
    def test_two_e_candidates(self): return self.check_candidates(["e", "e"])
    def test_many_e_candidates(self): return self.check_candidates(["e"] * 22)
    def test_one_s_candidate(self): return self.check_candidates(["s"])
    def test_two_s_candidates(self): return self.check_candidates(["s", "s"])
    def test_many_s_candidates(self): return self.check_candidates(["s"] * 22)
    def test_one_i_candidate(self): return self.check_candidates(["i"])
    def test_two_i_candidates(self): return self.check_candidates(["i", "i"])
    def test_many_i_candidates(self): return self.check_candidates(["i"] * 22)
    def test_one_d_candidate(self): return self.check_candidates(["d"])
    def test_two_d_candidates(self): return self.check_candidates(["d", "d"])
    def test_many_d_candidates(self): return self.check_candidates(["d"] * 22)
    def test_one_tw_candidate(self): return self.check_candidates(["tw"])
    def test_two_tw_candidates(self): return self.check_candidates(["tw", "tw"])
    def test_many_tw_candidates(self): return self.check_candidates(["tw"] * 22)
    def test_one_te_candidate(self): return self.check_candidates(["te"])
    def test_two_te_candidates(self): return self.check_candidates(["te", "te"])
    def test_many_te_candidates(self): return self.check_candidates(["te"] * 22)
    def test_one_ts_candidate(self): return self.check_candidates(["ts"])
    def test_two_ts_candidates(self): return self.check_candidates(["ts", "ts"])
    def test_many_ts_candidates(self): return self.check_candidates(["ts"] * 22)
    def test_one_ti_candidate(self): return self.check_candidates(["ti"])
    def test_two_ti_candidates(self): return self.check_candidates(["ti", "ti"])
    def test_many_ti_candidates(self): return self.check_candidates(["ti"] * 22)
    def test_one_td_candidate(self): return self.check_candidates(["td"])
    def test_two_td_candidates(self): return self.check_candidates(["td", "td"])
    def test_many_td_candidates(self): return self.check_candidates(["td"] * 22)
    def test_one_wr_candidate(self): return self.check_candidates(["wr"])
    def test_two_wr_candidates(self): return self.check_candidates(["wr", "wr"])
    def test_many_wr_candidates(self): return self.check_candidates(["wr"] * 22)
    def test_one_ws_candidate(self): return self.check_candidates(["ws"])
    def test_two_ws_candidates(self): return self.check_candidates(["ws", "ws"])
    def test_many_ws_candidates(self): return self.check_candidates(["ws"] * 22)
    def test_one_wi_candidate(self): return self.check_candidates(["wi"])
    def test_two_wi_candidates(self): return self.check_candidates(["wi", "wi"])
    def test_many_wi_candidates(self): return self.check_candidates(["wi"] * 22)
    def test_one_wd_candidate(self): return self.check_candidates(["wd"])
    def test_two_wd_candidates(self): return self.check_candidates(["wd", "wd"])
    def test_many_wd_candidates(self): return self.check_candidates(["wd"] * 22)
    def test_one_es_candidate(self): return self.check_candidates(["es"])
    def test_two_es_candidates(self): return self.check_candidates(["es", "es"])
    def test_many_es_candidates(self): return self.check_candidates(["es"] * 22)
    def test_one_ei_candidate(self): return self.check_candidates(["ei"])
    def test_two_ei_candidates(self): return self.check_candidates(["ei", "ei"])
    def test_many_ei_candidates(self): return self.check_candidates(["ei"] * 22)
    def test_one_ed_candidate(self): return self.check_candidates(["ed"])
    def test_two_ed_candidates(self): return self.check_candidates(["ed", "ed"])
    def test_many_ed_candidates(self): return self.check_candidates(["ed"] * 22)
    def test_one_si_candidate(self): return self.check_candidates(["si"])
    def test_two_si_candidates(self): return self.check_candidates(["si", "si"])
    def test_many_si_candidates(self): return self.check_candidates(["si"] * 22)
    def test_one_sd_candidate(self): return self.check_candidates(["sd"])
    def test_two_sd_candidates(self): return self.check_candidates(["sd", "sd"])
    def test_many_sd_candidates(self): return self.check_candidates(["sd"] * 22)
    def test_one_id_candidate(self): return self.check_candidates(["id"])
    def test_two_id_candidates(self): return self.check_candidates(["id", "id"])
    def test_many_id_candidates(self): return self.check_candidates(["id"] * 22)
    def test_one_twr_candidate(self): return self.check_candidates(["twr"])
    def test_two_twr_candidates(self): return self.check_candidates(["twr", "twr"])
    def test_many_twr_candidates(self): return self.check_candidates(["twr"] * 22)
    def test_one_tws_candidate(self): return self.check_candidates(["tws"])
    def test_two_tws_candidates(self): return self.check_candidates(["tws", "tws"])
    def test_many_tws_candidates(self): return self.check_candidates(["tws"] * 22)
    def test_one_twi_candidate(self): return self.check_candidates(["twi"])
    def test_two_twi_candidates(self): return self.check_candidates(["twi", "twi"])
    def test_many_twi_candidates(self): return self.check_candidates(["twi"] * 22)
    def test_one_twd_candidate(self): return self.check_candidates(["twd"])
    def test_two_twd_candidates(self): return self.check_candidates(["twd", "twd"])
    def test_many_twd_candidates(self): return self.check_candidates(["twd"] * 22)
    def test_one_tes_candidate(self): return self.check_candidates(["tes"])
    def test_two_tes_candidates(self): return self.check_candidates(["tes", "tes"])
    def test_many_tes_candidates(self): return self.check_candidates(["tes"] * 22)
    def test_one_tei_candidate(self): return self.check_candidates(["tei"])
    def test_two_tei_candidates(self): return self.check_candidates(["tei", "tei"])
    def test_many_tei_candidates(self): return self.check_candidates(["tei"] * 22)
    def test_one_ted_candidate(self): return self.check_candidates(["ted"])
    def test_two_ted_candidates(self): return self.check_candidates(["ted", "ted"])
    def test_many_ted_candidates(self): return self.check_candidates(["ted"] * 22)
    def test_one_tsi_candidate(self): return self.check_candidates(["tsi"])
    def test_two_tsi_candidates(self): return self.check_candidates(["tsi", "tsi"])
    def test_many_tsi_candidates(self): return self.check_candidates(["tsi"] * 22)
    def test_one_tsd_candidate(self): return self.check_candidates(["tsd"])
    def test_two_tsd_candidates(self): return self.check_candidates(["tsd", "tsd"])
    def test_many_tsd_candidates(self): return self.check_candidates(["tsd"] * 22)
    def test_one_tid_candidate(self): return self.check_candidates(["tid"])
    def test_two_tid_candidates(self): return self.check_candidates(["tid", "tid"])
    def test_many_tid_candidates(self): return self.check_candidates(["tid"] * 22)
    def test_one_wrs_candidate(self): return self.check_candidates(["wrs"])
    def test_two_wrs_candidates(self): return self.check_candidates(["wrs", "wrs"])
    def test_many_wrs_candidates(self): return self.check_candidates(["wrs"] * 22)
    def test_one_wri_candidate(self): return self.check_candidates(["wri"])
    def test_two_wri_candidates(self): return self.check_candidates(["wri", "wri"])
    def test_many_wri_candidates(self): return self.check_candidates(["wri"] * 22)
    def test_one_wrd_candidate(self): return self.check_candidates(["wrd"])
    def test_two_wrd_candidates(self): return self.check_candidates(["wrd", "wrd"])
    def test_many_wrd_candidates(self): return self.check_candidates(["wrd"] * 22)
    def test_one_wsi_candidate(self): return self.check_candidates(["wsi"])
    def test_two_wsi_candidates(self): return self.check_candidates(["wsi", "wsi"])
    def test_many_wsi_candidates(self): return self.check_candidates(["wsi"] * 22)
    def test_one_wsd_candidate(self): return self.check_candidates(["wsd"])
    def test_two_wsd_candidates(self): return self.check_candidates(["wsd", "wsd"])
    def test_many_wsd_candidates(self): return self.check_candidates(["wsd"] * 22)
    def test_one_wid_candidate(self): return self.check_candidates(["wid"])
    def test_two_wid_candidates(self): return self.check_candidates(["wid", "wid"])
    def test_many_wid_candidates(self): return self.check_candidates(["wid"] * 22)
    def test_one_esi_candidate(self): return self.check_candidates(["esi"])
    def test_two_esi_candidates(self): return self.check_candidates(["esi", "esi"])
    def test_many_esi_candidates(self): return self.check_candidates(["esi"] * 22)
    def test_one_esd_candidate(self): return self.check_candidates(["esd"])
    def test_two_esd_candidates(self): return self.check_candidates(["esd", "esd"])
    def test_many_esd_candidates(self): return self.check_candidates(["esd"] * 22)
    def test_one_eid_candidate(self): return self.check_candidates(["eid"])
    def test_two_eid_candidates(self): return self.check_candidates(["eid", "eid"])
    def test_many_eid_candidates(self): return self.check_candidates(["eid"] * 22)
    def test_one_sid_candidate(self): return self.check_candidates(["sid"])
    def test_two_sid_candidates(self): return self.check_candidates(["sid", "sid"])
    def test_many_sid_candidates(self): return self.check_candidates(["sid"] * 22)
    def test_one_twrs_candidate(self): return self.check_candidates(["twrs"])
    def test_two_twrs_candidates(self): return self.check_candidates(["twrs", "twrs"])
    def test_many_twrs_candidates(self): return self.check_candidates(["twrs"] * 22)
    def test_one_twri_candidate(self): return self.check_candidates(["twri"])
    def test_two_twri_candidates(self): return self.check_candidates(["twri", "twri"])
    def test_many_twri_candidates(self): return self.check_candidates(["twri"] * 22)
    def test_one_twrd_candidate(self): return self.check_candidates(["twrd"])
    def test_two_twrd_candidates(self): return self.check_candidates(["twrd", "twrd"])
    def test_many_twrd_candidates(self): return self.check_candidates(["twrd"] * 22)
    def test_one_twsi_candidate(self): return self.check_candidates(["twsi"])
    def test_two_twsi_candidates(self): return self.check_candidates(["twsi", "twsi"])
    def test_many_twsi_candidates(self): return self.check_candidates(["twsi"] * 22)
    def test_one_twsd_candidate(self): return self.check_candidates(["twsd"])
    def test_two_twsd_candidates(self): return self.check_candidates(["twsd", "twsd"])
    def test_many_twsd_candidates(self): return self.check_candidates(["twsd"] * 22)
    def test_one_twid_candidate(self): return self.check_candidates(["twid"])
    def test_two_twid_candidates(self): return self.check_candidates(["twid", "twid"])
    def test_many_twid_candidates(self): return self.check_candidates(["twid"] * 22)
    def test_one_tesi_candidate(self): return self.check_candidates(["tesi"])
    def test_two_tesi_candidates(self): return self.check_candidates(["tesi", "tesi"])
    def test_many_tesi_candidates(self): return self.check_candidates(["tesi"] * 22)
    def test_one_tesd_candidate(self): return self.check_candidates(["tesd"])
    def test_two_tesd_candidates(self): return self.check_candidates(["tesd", "tesd"])
    def test_many_tesd_candidates(self): return self.check_candidates(["tesd"] * 22)
    def test_one_teid_candidate(self): return self.check_candidates(["teid"])
    def test_two_teid_candidates(self): return self.check_candidates(["teid", "teid"])
    def test_many_teid_candidates(self): return self.check_candidates(["teid"] * 22)
    def test_one_tsid_candidate(self): return self.check_candidates(["tsid"])
    def test_two_tsid_candidates(self): return self.check_candidates(["tsid", "tsid"])
    def test_many_tsid_candidates(self): return self.check_candidates(["tsid"] * 22)
    def test_one_wrsi_candidate(self): return self.check_candidates(["wrsi"])
    def test_two_wrsi_candidates(self): return self.check_candidates(["wrsi", "wrsi"])
    def test_many_wrsi_candidates(self): return self.check_candidates(["wrsi"] * 22)
    def test_one_wrsd_candidate(self): return self.check_candidates(["wrsd"])
    def test_two_wrsd_candidates(self): return self.check_candidates(["wrsd", "wrsd"])
    def test_many_wrsd_candidates(self): return self.check_candidates(["wrsd"] * 22)
    def test_one_wrid_candidate(self): return self.check_candidates(["wrid"])
    def test_two_wrid_candidates(self): return self.check_candidates(["wrid", "wrid"])
    def test_many_wrid_candidates(self): return self.check_candidates(["wrid"] * 22)
    def test_one_wsid_candidate(self): return self.check_candidates(["wsid"])
    def test_two_wsid_candidates(self): return self.check_candidates(["wsid", "wsid"])
    def test_many_wsid_candidates(self): return self.check_candidates(["wsid"] * 22)
    def test_one_esid_candidate(self): return self.check_candidates(["esid"])
    def test_two_esid_candidates(self): return self.check_candidates(["esid", "esid"])
    def test_many_esid_candidates(self): return self.check_candidates(["esid"] * 22)
    def test_one_twrsi_candidate(self): return self.check_candidates(["twrsi"])
    def test_two_twrsi_candidates(self): return self.check_candidates(["twrsi", "twrsi"])
    def test_many_twrsi_candidates(self): return self.check_candidates(["twrsi"] * 22)
    def test_one_twrsd_candidate(self): return self.check_candidates(["twrsd"])
    def test_two_twrsd_candidates(self): return self.check_candidates(["twrsd", "twrsd"])
    def test_many_twrsd_candidates(self): return self.check_candidates(["twrsd"] * 22)
    def test_one_twrid_candidate(self): return self.check_candidates(["twrid"])
    def test_two_twrid_candidates(self): return self.check_candidates(["twrid", "twrid"])
    def test_many_twrid_candidates(self): return self.check_candidates(["twrid"] * 22)
    def test_one_twsid_candidate(self): return self.check_candidates(["twsid"])
    def test_two_twsid_candidates(self): return self.check_candidates(["twsid", "twsid"])
    def test_many_twsid_candidates(self): return self.check_candidates(["twsid"] * 22)
    def test_one_tesid_candidate(self): return self.check_candidates(["tesid"])
    def test_two_tesid_candidates(self): return self.check_candidates(["tesid", "tesid"])
    def test_many_tesid_candidates(self): return self.check_candidates(["tesid"] * 22)
    def test_one_wrsid_candidate(self): return self.check_candidates(["wrsid"])
    def test_two_wrsid_candidates(self): return self.check_candidates(["wrsid", "wrsid"])
    def test_many_wrsid_candidates(self): return self.check_candidates(["wrsid"] * 22)
    def test_one_twrsid_candidate(self): return self.check_candidates(["twrsid"])
    def test_two_twrsid_candidates(self): return self.check_candidates(["twrsid", "twrsid"])
    def test_many_twrsid_candidates(self): return self.check_candidates(["twrsid"] * 22)
    def test_mixed_1_candidates(self): return self.check_candidates([''])
    def test_mixed_2_candidates(self): return self.check_candidates(['', 't'])
    def test_mixed_3_candidates(self): return self.check_candidates(['', 't', 'w'])
    def test_mixed_4_candidates(self): return self.check_candidates(['', 't', 'w', 'e'])
    def test_mixed_5_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's'])
    def test_mixed_6_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i'])
    def test_mixed_7_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd'])
    def test_mixed_8_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw'])
    def test_mixed_9_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te'])
    def test_mixed_10_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts'])
    def test_mixed_11_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti'])
    def test_mixed_12_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td'])
    def test_mixed_13_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr'])
    def test_mixed_14_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws'])
    def test_mixed_15_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi'])
    def test_mixed_16_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd'])
    def test_mixed_17_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es'])
    def test_mixed_18_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei'])
    def test_mixed_19_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed'])
    def test_mixed_20_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si'])
    def test_mixed_21_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd'])
    def test_mixed_22_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id'])
    def test_mixed_23_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr'])
    def test_mixed_24_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws'])
    def test_mixed_25_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi'])
    def test_mixed_26_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd'])
    def test_mixed_27_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes'])
    def test_mixed_28_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei'])
    def test_mixed_29_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted'])
    def test_mixed_30_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi'])
    def test_mixed_31_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd'])
    def test_mixed_32_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid'])
    def test_mixed_33_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs'])
    def test_mixed_34_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri'])
    def test_mixed_35_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd'])
    def test_mixed_36_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi'])
    def test_mixed_37_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd'])
    def test_mixed_38_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid'])
    def test_mixed_39_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi'])
    def test_mixed_40_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd'])
    def test_mixed_41_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid'])
    def test_mixed_42_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid'])
    def test_mixed_43_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs'])
    def test_mixed_44_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri'])
    def test_mixed_45_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd'])
    def test_mixed_46_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi'])
    def test_mixed_47_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd'])
    def test_mixed_48_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid'])
    def test_mixed_49_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi'])
    def test_mixed_50_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd'])
    def test_mixed_51_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid'])
    def test_mixed_52_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid'])
    def test_mixed_53_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi'])
    def test_mixed_54_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd'])
    def test_mixed_55_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid'])
    def test_mixed_56_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid', 'wsid'])
    def test_mixed_57_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid', 'wsid', 'esid'])
    def test_mixed_58_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid', 'wsid', 'esid', 'twrsi'])
    def test_mixed_59_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid', 'wsid', 'esid', 'twrsi', 'twrsd'])
    def test_mixed_60_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid', 'wsid', 'esid', 'twrsi', 'twrsd', 'twrid'])
    def test_mixed_61_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid', 'wsid', 'esid', 'twrsi', 'twrsd', 'twrid', 'twsid'])
    def test_mixed_62_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid', 'wsid', 'esid', 'twrsi', 'twrsd', 'twrid', 'twsid', 'tesid'])
    def test_mixed_63_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid', 'wsid', 'esid', 'twrsi', 'twrsd', 'twrid', 'twsid', 'tesid', 'wrsid'])
    def test_mixed_64_candidates(self): return self.check_candidates(['', 't', 'w', 'e', 's', 'i', 'd', 'tw', 'te', 'ts', 'ti', 'td', 'wr', 'ws', 'wi', 'wd', 'es', 'ei', 'ed', 'si', 'sd', 'id', 'twr', 'tws', 'twi', 'twd', 'tes', 'tei', 'ted', 'tsi', 'tsd', 'tid', 'wrs', 'wri', 'wrd', 'wsi', 'wsd', 'wid', 'esi', 'esd', 'eid', 'sid', 'twrs', 'twri', 'twrd', 'twsi', 'twsd', 'twid', 'tesi', 'tesd', 'teid', 'tsid', 'wrsi', 'wrsd', 'wrid', 'wsid', 'esid', 'twrsi', 'twrsd', 'twrid', 'twsid', 'tesid', 'wrsid', 'twrsid'])

    def create_candidates(self, community, all_flags):
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)
        def generator():
            for port, flags in enumerate(all_flags, 1):
                address = ("127.0.0.1", port)
                tunnel = "t" in flags
                yield community.create_candidate(address, tunnel, address, address, u"unknown")

        with community.dispersy.database:
            return list(generator())

    def set_timestamps(self, candidates, all_flags):
        assert isinstance(candidates, list)
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)
        now = time()
        for flags, candidate in zip(all_flags, candidates):
            member = [None]

            def get_member():
                if not member[0]:
                    member[0] = self._dispersy.get_new_member(u"very-low")
                return member[0]

            if "w" in flags:
                # SELF has performed an outgoing walk to CANDIDATE
                candidate.walk(now)
                assert candidate.last_walk == now

            if "r" in flags:
                # SELF has received an incoming walk response from CANDIDATE
                candidate.associate(get_member())
                candidate.walk_response(now)
                assert candidate.last_walk_reply == now

            if "e" in flags:
                # CANDIDATE_ELIGIBLE_DELAY seconds ago SELF performed a successful walk to CANDIDATE
                candidate.associate(get_member())
                candidate.walk(now - CANDIDATE_ELIGIBLE_DELAY)
                candidate.walk_response(now)
                assert candidate.last_walk_reply == now, (candidate.last_walk_reply)

            if "s" in flags:
                # SELF has received an incoming walk request from CANDIDATE
                candidate.associate(get_member())
                candidate.stumble(now)
                assert candidate.last_stumble == now

            if "i" in flags:
                # SELF has received an incoming walk response which introduced CANDIDATE
                candidate.intro(now)
                assert candidate.last_intro == now

            if "d" in flags:
                # SELF was discovered
                candidate.discovered(now)
                assert candidate.last_discovered == now

        return now

    def select_candidates(self, candidates, all_flags):
        def filter_func(flags):
            """
            Returns True when the flags correspond with a Candidate that should be returned by
            dispersy_yield_candidates.
            """
            return ("s" in flags or "e" in flags or "i" in flags or "r" in flags)

        return [candidate for flags, candidate in zip(all_flags, candidates) if filter_func(flags)]

    def select_verified_candidates(self, candidates, all_flags):
        def filter_func(flags):
            """
            Returns True when the flags correspond with a Candidate that should be returned by
            dispersy_yield_verified_candidates.
            """
            return ("s" in flags or "e" in flags or "r" in flags)

        return [candidate for flags, candidate in zip(all_flags, candidates) if filter_func(flags)]

    def select_walk_candidates(self, candidates, all_flags):
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

            if "d" in flags and not "w" in flags:
                # the candidate has the 'discovered' but not the 'walk' flag, i.e. it is known but we have not recently
                # walked towards it
                return True

            return False

        return [candidate for flags, candidate in zip(all_flags, candidates) if filter_func(flags)]

    def select_introduce_candidates(self, candidates, all_flags, exclude_candidate=None):
        def filter_func(flags, candidate):
            """
            Returns True when the flags correspond with a Candidate that should be returned by
            dispersy_get_introduce_candidate.
            """
            if exclude_candidate:
                if exclude_candidate == candidate:
                    return

                if not exclude_candidate.tunnel and candidate.tunnel:
                    return

            if "s" in flags:
                return True

            if "e" in flags:
                return True

            if "r" in flags:
                return True

        return [candidate for flags, candidate in zip(all_flags, candidates) if filter_func(flags, candidate)]

    @blocking_call_on_reactor_thread
    def check_candidates(self, all_flags):
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)

        def compare(selection, actual):
            selection = set(["%s:%d" % c.sock_addr if c else None for c in selection])
            actual = set(["%s:%d" % c.sock_addr if c else None for c in actual])
            try:
                self.assertEquals(selection, actual)
            except:
                self._logger.error("FLAGS %s", all_flags)
                self._logger.error("SELECT %s", sorted(selection))
                self._logger.error("ACTUAL %s", sorted(actual))
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
        community = NoBootstrapDebugCommunity.create_community(self._dispersy, self._mm._my_member)
        candidates = self.create_candidates(community, all_flags)

        # yield_candidates
        self.set_timestamps(candidates, all_flags)
        selection = self.select_candidates(candidates, all_flags)
        actual_list = [islice(community.dispersy_yield_candidates(), max_iterations) for _ in xrange(max_calls)]
        for actual in actual_list:
            compare(selection, actual)

        # yield_verified_candidates
        self.set_timestamps(candidates, all_flags)
        selection = self.select_verified_candidates(candidates, all_flags)
        actual_list = [islice(community.dispersy_yield_verified_candidates(), max_iterations)
                       for _ in xrange(max_calls)]
        for actual in actual_list:
            compare(selection, actual)

        # get_introduce_candidate (no exclusion)
        self.set_timestamps(candidates, all_flags)
        selection = self.select_introduce_candidates(candidates, all_flags) or [None]
        actual = [community.dispersy_get_introduce_candidate() for _ in xrange(max_calls)]
        compare(selection, actual)

        # get_introduce_candidate (with exclusion)
        self.set_timestamps(candidates, all_flags)
        for candidate in candidates:
            selection = self.select_introduce_candidates(candidates, all_flags, candidate) or [None]
            actual = [community.dispersy_get_introduce_candidate(candidate) for _ in xrange(max_calls)]
            compare(selection, actual)

        # get_walk_candidate
        # Note that we must perform the CANDIDATE.WALK to ensure this candidate is not iterated again.  Because of this,
        # this test must be done last.
        self.set_timestamps(candidates, all_flags)
        selection = self.select_walk_candidates(candidates, all_flags)
        for _ in xrange(len(selection)):
            candidate = community.dispersy_get_walk_candidate()
            self.assertNotEquals(candidate, None)
            self.assertIn("%s:%d" % candidate.sock_addr, ["%s:%d" % c.sock_addr for c in selection])
            candidate.walk(time())
            assert candidate.is_eligible_for_walk(time()) == False

        # after walking to all candidates we cannot walk to anyone
        candidate = community.dispersy_get_walk_candidate()
        self.assertEquals(candidate, None)

    @blocking_call_on_reactor_thread
    def test_get_introduce_candidate(self, community_create_method=DebugCommunity.create_community):
        community = community_create_method(self._dispersy, self._community._my_member)
        candidates = self.create_candidates(community, [""] * 5)
        expected = [None, ("127.0.0.1", 1), ("127.0.0.1", 2), ("127.0.0.1", 3), ("127.0.0.1", 4)]
        now = time()
        got = []
        for candidate in candidates:
            candidate.associate(self._dispersy.get_new_member(u"very-low"))
            candidate.stumble(now)
            introduce = community.dispersy_get_introduce_candidate(candidate)
            got.append(introduce.sock_addr if introduce else None)
        self.assertEquals(expected, got)

        return community, candidates

    @blocking_call_on_reactor_thread
    def test_keep_alive_candidate(self, community_create_method=TrackerCommunity.create_community):
        community = community_create_method(self._dispersy, self._community._my_member)
        candidate = self.create_candidates(community, ["r", ])[0]
        candidate.set_keepalive(community)
        candidate.associate(self._dispersy.get_new_member(u"very-low"))

        # Make this a walk candidate
        candidate.walk_response(time())
        self.assertEqual(u"walk", candidate.get_category(time()))

        # Fake timeout
        candidate.walk_response(time())
        category = candidate.get_category(time()+CANDIDATE_LIFETIME+1.0)

        self.assertEqual(u"walk", category)
        self.assertGreater(candidate.last_walk_reply, -1.0)

    @blocking_call_on_reactor_thread
    def test_keep_alive_candidate_timeout(self, community_create_method=TrackerCommunity.create_community):
        community = community_create_method(self._dispersy, self._community._my_member)
        candidate = self.create_candidates(community, ["r", ])[0]
        candidate.set_keepalive(community)
        candidate.associate(self._dispersy.get_new_member(u"very-low"))

        # Make this a walk candidate
        candidate.walk_response(time())
        self.assertEqual(u"walk", candidate.get_category(time()))

        # Fake timeout
        candidate.walk_response(time())
        candidate.get_category(time()+CANDIDATE_LIFETIME+1.0)

        # Faked timeout again
        candidate.walk_response(time()+CANDIDATE_LIFETIME+1.0)
        category = candidate.get_category(time()+2*CANDIDATE_LIFETIME+2.0)

        self.assertIsNone(category)

    @blocking_call_on_reactor_thread
    def test_tracker_get_introduce_candidate(self, community_create_method=TrackerCommunity.create_community):
        community, candidates = self.test_get_introduce_candidate(community_create_method)

        # trackers should not prefer either stumbled or walked candidates, i.e. it should not return
        # candidate 1 more than once/in the wrong position
        now = time()
        expected = [("127.0.0.1", 5), ("127.0.0.1", 1), ("127.0.0.1", 2), ("127.0.0.1", 3), ("127.0.0.1", 4)]
        got = []
        for candidate in candidates:
            candidate.stumble(now)
            introduce = community.dispersy_get_introduce_candidate(candidate)
            got.append(introduce.sock_addr if introduce else None)
        self.assertEquals(expected, got)

    @blocking_call_on_reactor_thread
    def test_introduction_probabilities(self):
        candidates = self.create_candidates(self._community, ["wr", "s"])
        self.set_timestamps(candidates, ["wr", "s"])

        # fetch candidates
        returned_walked_candidate = 0
        expected_walked_range = range(4500, 5500)
        for _ in xrange(10000):
            candidate = self._community.dispersy_get_introduce_candidate()
            returned_walked_candidate += 1 if candidate.sock_addr[1] == 1 else 0

        assert returned_walked_candidate in expected_walked_range

    @blocking_call_on_reactor_thread
    def test_walk_probabilities(self):
        candidates = self.create_candidates(self._community, ["e", "s", "i", "d"])
        self.set_timestamps(candidates, ["e", "s", "i", "d"])

        # fetch candidates
        returned_walked_candidate = 0
        expected_walked_range = .475
        returned_stumble_candidate = 0
        expected_stumble_range = .475 / 2
        returned_intro_candidate = 0
        expected_intro_range = .475 / 2
        returned_discovered_candidate = 0
        expected_discovered_range = .05
        assert expected_walked_range + expected_stumble_range + expected_intro_range + expected_discovered_range == 1.0

        for i in xrange(10000):
            candidate = self._community.dispersy_get_walk_candidate()

            returned_walked_candidate += 1 if candidate.sock_addr[1] == 1 else 0
            returned_stumble_candidate += 1 if candidate.sock_addr[1] == 2 else 0
            returned_intro_candidate += 1 if candidate.sock_addr[1] == 3 else 0
            returned_discovered_candidate += 1 if candidate.sock_addr[1] == 4 else 0

        assert returned_walked_candidate in range(int(expected_walked_range * 9000),
                                                  int(expected_walked_range * 11000)), returned_walked_candidate
        assert returned_stumble_candidate in range(int(expected_stumble_range * 9000),
                                                   int(expected_stumble_range * 11000)), returned_stumble_candidate
        assert returned_intro_candidate in range(int(expected_intro_range * 9000),
                                                 int(expected_intro_range * 11000)), returned_intro_candidate
        assert returned_discovered_candidate in range(int(expected_discovered_range * 9000),
                                                      int(expected_discovered_range * 11000)), returned_discovered_candidate

    @blocking_call_on_reactor_thread
    def test_merge_candidates(self):
        # let's make a list of all possible combinations which should be merged into one candidate
        candidates = []
        candidates.append(self._community.create_candidate(("1.1.1.1", 1), False, ("192.168.0.1", 1),
                                                           ("1.1.1.1", 1), u"unknown"))
        candidates.append(self._community.create_candidate(("1.1.1.1", 2), False, ("192.168.0.1", 1),
                                                           ("1.1.1.1", 2), u"symmetric-NAT"))
        candidates.append(self._community.create_candidate(("1.1.1.1", 3), False, ("192.168.0.1", 1),
                                                           ("1.1.1.1", 3), u"symmetric-NAT"))
        candidates.append(self._community.create_candidate(("1.1.1.1", 4), False, ("192.168.0.1", 1),
                                                           ("1.1.1.1", 4), u"unknown"))

        self._community.filter_duplicate_candidate(candidates[0])

        expected = [candidates[0].wan_address]

        got = []
        for candidate in self._community._candidates.itervalues():
            got.append(candidate.wan_address)

        self.assertEquals(expected, got)
