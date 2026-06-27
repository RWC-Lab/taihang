In the following speed table, smaller numbers are better.
The numbers are interquartile means of single-core cycle counts on various microarchitectures.
Overclocking is disabled.

The table reports cycle counts from lib25519 and, for comparison,
OpenSSL and s2n-bignum.
For comparability to OpenSSL's speed-testing utility,
the OpenSSL cycle counts omit various OpenSSL overheads; see below for details.
The s2n-bignum and lib25519 cycle counts include all overheads.
There is also a lib25519+s2n line showing separate measurements of lib25519
after an optional pre-configuration `./use-s2n-bignum` step
(which is a supported option for lib25519);
a lib25519+exp line showing separate measurements of lib25519
after an experimental pre-configuration `mv skipcompilers/* compilers` step
(which is unsupported: it uses instructions not supported by `valgrind`);
and a lib25519+s2n+exp line.


| μarch | software | X key | X dh | X batch | Ed key | Ed sign | Ed verif | Ed MSM |
| :---- | :------- | ----: | ---: | ------: | -----: | ------: | -------: | -----: |
| Intel Redwood Cove (2023) | <span class=openssl>OpenSSL</span> | <span class=openssl>102655</span> | <span class=openssl>103510</span> | | <span class=openssl>106608</span> | <span class=openssl>103247</span> | <span class=openssl>341443</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>23202</span> | <span class=lib25519>94878</span> | <span class=lib25519>63162</span> | <span class=lib25519>24481</span> | <span class=lib25519>27407</span> | <span class=lib25519>96199</span> | <span class=lib25519>30320
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>23345</span> | <span class=lib25519>67631</span> | <span class=lib25519>62627</span> | <span class=lib25519>24132</span> | <span class=lib25519>27683</span> | <span class=lib25519>93290</span> | <span class=lib25519>29890
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>23642</span> | <span class=lib25519>67570</span> | <span class=lib25519>62662</span> | <span class=lib25519>24103</span> | <span class=lib25519>27934</span> | <span class=lib25519>93889</span> | <span class=lib25519>29463
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>24140</span> | <span class=lib25519>94798</span> | <span class=lib25519>63032</span> | <span class=lib25519>24287</span> | <span class=lib25519>27932</span> | <span class=lib25519>94654</span> | <span class=lib25519>30479
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>24669</span> | <span class=s2n>75760</span> | | | | | |
| AMD Zen 4 (2022) | <span class=openssl>OpenSSL</span> | <span class=openssl>111574</span> | <span class=openssl>109143</span> | | <span class=openssl>114875</span> | <span class=openssl>110739</span> | <span class=openssl>378734</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>27981</span> | <span class=lib25519>70915</span> | <span class=lib25519>45918</span> | <span class=lib25519>28641</span> | <span class=lib25519>31993</span> | <span class=lib25519>123236</span> | <span class=lib25519>38862
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>22731</span> | <span class=lib25519>53572</span> | <span class=lib25519>22362</span> | <span class=lib25519>23522</span> | <span class=lib25519>26680</span> | <span class=lib25519>111059</span> | <span class=lib25519>34695
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>22697</span> | <span class=lib25519>53535</span> | <span class=lib25519>22478</span> | <span class=lib25519>23463</span> | <span class=lib25519>26706</span> | <span class=lib25519>113579</span> | <span class=lib25519>34551
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>27990</span> | <span class=lib25519>71140</span> | <span class=lib25519>45752</span> | <span class=lib25519>28720</span> | <span class=lib25519>31793</span> | <span class=lib25519>124290</span> | <span class=lib25519>38900
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>26471</span> | <span class=s2n>87905</span> | | | | | |
| Intel Golden Cove (2021) | <span class=openssl>OpenSSL</span> | <span class=openssl>98110</span> | <span class=openssl>104590</span> | | <span class=openssl>99827</span> | <span class=openssl>98099</span> | <span class=openssl>331861</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>25446</span> | <span class=lib25519>83586</span> | <span class=lib25519>50346</span> | <span class=lib25519>24993</span> | <span class=lib25519>28114</span> | <span class=lib25519>96327</span> | <span class=lib25519>31080
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>23828</span> | <span class=lib25519>69036</span> | <span class=lib25519>49930</span> | <span class=lib25519>24981</span> | <span class=lib25519>29277</span> | <span class=lib25519>95024</span> | <span class=lib25519>30688
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>23926</span> | <span class=lib25519>67997</span> | <span class=lib25519>49888</span> | <span class=lib25519>25053</span> | <span class=lib25519>28602</span> | <span class=lib25519>96265</span> | <span class=lib25519>30279
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>24968</span> | <span class=lib25519>83546</span> | <span class=lib25519>50257</span> | <span class=lib25519>25311</span> | <span class=lib25519>28601</span> | <span class=lib25519>95184</span> | <span class=lib25519>31114
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>24124</span> | <span class=s2n>75653</span> | | | | | |
| AMD Zen 3 (2020) | <span class=openssl>OpenSSL</span> | <span class=openssl>112079</span> | <span class=openssl>117092</span> | | <span class=openssl>114230</span> | <span class=openssl>111564</span> | <span class=openssl>369827</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>28736</span> | <span class=lib25519>73082</span> | <span class=lib25519>71153</span> | <span class=lib25519>29047</span> | <span class=lib25519>32447</span> | <span class=lib25519>127996</span> | <span class=lib25519>40558
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>25731</span> | <span class=lib25519>73020</span> | <span class=lib25519>47919</span> | <span class=lib25519>26596</span> | <span class=lib25519>29986</span> | <span class=lib25519>112251</span> | <span class=lib25519>35542
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>25682</span> | <span class=lib25519>73039</span> | <span class=lib25519>47832</span> | <span class=lib25519>26555</span> | <span class=lib25519>29972</span> | <span class=lib25519>112717</span> | <span class=lib25519>35462
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>28242</span> | <span class=lib25519>73092</span> | <span class=lib25519>50367</span> | <span class=lib25519>29084</span> | <span class=lib25519>32402</span> | <span class=lib25519>126450</span> | <span class=lib25519>40762
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>26507</span> | <span class=s2n>88942</span> | | | | | |
| Intel Tiger Lake (2020) | <span class=openssl>OpenSSL</span> | <span class=openssl>116185</span> | <span class=openssl>122224</span> | | <span class=openssl>118890</span> | <span class=openssl>117272</span> | <span class=openssl>390023</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>29203</span> | <span class=lib25519>85377</span> | <span class=lib25519>61558</span> | <span class=lib25519>30114</span> | <span class=lib25519>33707</span> | <span class=lib25519>114388</span> | <span class=lib25519>34988
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>27477</span> | <span class=lib25519>64604</span> | <span class=lib25519>21678</span> | <span class=lib25519>28300</span> | <span class=lib25519>31917</span> | <span class=lib25519>108489</span> | <span class=lib25519>32574
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>27493</span> | <span class=lib25519>64623</span> | <span class=lib25519>21666</span> | <span class=lib25519>28302</span> | <span class=lib25519>31967</span> | <span class=lib25519>106086</span> | <span class=lib25519>32869
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>29493</span> | <span class=lib25519>85129</span> | <span class=lib25519>62324</span> | <span class=lib25519>30348</span> | <span class=lib25519>33880</span> | <span class=lib25519>113989</span> | <span class=lib25519>35743
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>27351</span> | <span class=s2n>83661</span> | | | | | |
| AMD Zen 2 (2019) | <span class=openssl>OpenSSL</span> | <span class=openssl>123476</span> | <span class=openssl>118444</span> | | <span class=openssl>125486</span> | <span class=openssl>120168</span> | <span class=openssl>398495</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>27763</span> | <span class=lib25519>112800</span> | <span class=lib25519>74459</span> | <span class=lib25519>28647</span> | <span class=lib25519>31844</span> | <span class=lib25519>129584</span> | <span class=lib25519>37850
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>27715</span> | <span class=lib25519>101021</span> | <span class=lib25519>74033</span> | <span class=lib25519>28425</span> | <span class=lib25519>31667</span> | <span class=lib25519>127971</span> | <span class=lib25519>38011
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>26759</span> | <span class=lib25519>95144</span> | <span class=lib25519>73685</span> | <span class=lib25519>27720</span> | <span class=lib25519>30967</span> | <span class=lib25519>127160</span> | <span class=lib25519>37956
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>27820</span> | <span class=lib25519>112841</span> | <span class=lib25519>74279</span> | <span class=lib25519>28529</span> | <span class=lib25519>31682</span> | <span class=lib25519>129086</span> | <span class=lib25519>38009
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>26478</span> | <span class=s2n>93099</span> | | | | | |
| ARM Neoverse N1 (2019) | <span class=openssl>OpenSSL</span> | <span class=openssl>99997</span> | <span class=openssl>392328</span> | | <span class=openssl>103377</span> | <span class=openssl>99389</span> | <span class=openssl>328870</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>50101</span> | <span class=lib25519>115215</span> | <span class=lib25519>115058</span> | <span class=lib25519>51010</span> | <span class=lib25519>55528</span> | <span class=lib25519>244068</span> | <span class=lib25519>72660
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>50219</span> | <span class=lib25519>115190</span> | <span class=lib25519>115062</span> | <span class=lib25519>51170</span> | <span class=lib25519>55601</span> | <span class=lib25519>244691</span> | <span class=lib25519>72905
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>49968</span> | <span class=lib25519>111647</span> | <span class=lib25519>111537</span> | <span class=lib25519>50974</span> | <span class=lib25519>55481</span> | <span class=lib25519>242377</span> | <span class=lib25519>73082
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>50130</span> | <span class=lib25519>111624</span> | <span class=lib25519>111534</span> | <span class=lib25519>50982</span> | <span class=lib25519>55603</span> | <span class=lib25519>241601</span> | <span class=lib25519>72922
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>53028</span> | <span class=s2n>111822</span> | | | | | |
| ARM Cortex-A76 (2018) | <span class=openssl>OpenSSL</span> | <span class=openssl>98208</span> | <span class=openssl>392220</span> | | <span class=openssl>100316</span> | <span class=openssl>98058</span> | <span class=openssl>328523</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>49290</span> | <span class=lib25519>115105</span> | <span class=lib25519>115061</span> | <span class=lib25519>50211</span> | <span class=lib25519>54872</span> | <span class=lib25519>242570</span> | <span class=lib25519>72591
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>49221</span> | <span class=lib25519>115111</span> | <span class=lib25519>115050</span> | <span class=lib25519>50182</span> | <span class=lib25519>54746</span> | <span class=lib25519>245004</span> | <span class=lib25519>72870
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>49223</span> | <span class=lib25519>111516</span> | <span class=lib25519>111522</span> | <span class=lib25519>50131</span> | <span class=lib25519>54766</span> | <span class=lib25519>242067</span> | <span class=lib25519>72938
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>49165</span> | <span class=lib25519>111529</span> | <span class=lib25519>111522</span> | <span class=lib25519>50259</span> | <span class=lib25519>54687</span> | <span class=lib25519>243189</span> | <span class=lib25519>72746
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>49949</span> | <span class=s2n>111541</span> | | | | | |
| Intel Goldmont Plus (2017) | <span class=openssl>OpenSSL</span> | <span class=openssl>216237</span> | <span class=openssl>252134</span> | | <span class=openssl>222984</span> | <span class=openssl>214318</span> | <span class=openssl>711629</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>84907</span> | <span class=lib25519>267290</span> | <span class=lib25519>265772</span> | <span class=lib25519>87040</span> | <span class=lib25519>95621</span> | <span class=lib25519>315405</span> | <span class=lib25519>88459
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>84047</span> | <span class=lib25519>267123</span> | <span class=lib25519>267303</span> | <span class=lib25519>86232</span> | <span class=lib25519>94734</span> | <span class=lib25519>314777</span> | <span class=lib25519>88729
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>68275</span> | <span class=lib25519>245750</span> | <span class=lib25519>245746</span> | <span class=lib25519>70395</span> | <span class=lib25519>78853</span> | <span class=lib25519>298975</span> | <span class=lib25519>87383
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>69205</span> | <span class=lib25519>245752</span> | <span class=lib25519>245760</span> | <span class=lib25519>71299</span> | <span class=lib25519>79804</span> | <span class=lib25519>298539</span> | <span class=lib25519>87279
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>69563</span> | <span class=s2n>245712</span> | | | | | |
| ARM Cortex-A72 (2016) | <span class=openssl>OpenSSL</span> | <span class=openssl>138448</span> | <span class=openssl>423947</span> | | <span class=openssl>145529</span> | <span class=openssl>129518</span> | <span class=openssl>398640</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>60844</span> | <span class=lib25519>129860</span> | <span class=lib25519>129863</span> | <span class=lib25519>62310</span> | <span class=lib25519>68159</span> | <span class=lib25519>288050</span> | <span class=lib25519>87706
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>60788</span> | <span class=lib25519>129858</span> | <span class=lib25519>129872</span> | <span class=lib25519>62275</span> | <span class=lib25519>68103</span> | <span class=lib25519>286528</span> | <span class=lib25519>88048
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>58798</span> | <span class=lib25519>128022</span> | <span class=lib25519>128019</span> | <span class=lib25519>60297</span> | <span class=lib25519>66010</span> | <span class=lib25519>284735</span> | <span class=lib25519>88262
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>58670</span> | <span class=lib25519>128021</span> | <span class=lib25519>128013</span> | <span class=lib25519>60174</span> | <span class=lib25519>65913</span> | <span class=lib25519>282192</span> | <span class=lib25519>87552
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>60466</span> | <span class=s2n>136537</span> | | | | | |
| Intel Skylake (2015) | <span class=openssl>OpenSSL</span> | <span class=openssl>123177</span> | <span class=openssl>118572</span> | | <span class=openssl>125842</span> | <span class=openssl>120298</span> | <span class=openssl>392874</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>33440</span> | <span class=lib25519>88172</span> | <span class=lib25519>62840</span> | <span class=lib25519>34288</span> | <span class=lib25519>37708</span> | <span class=lib25519>116074</span> | <span class=lib25519>37912
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>31381</span> | <span class=lib25519>83219</span> | <span class=lib25519>62875</span> | <span class=lib25519>32131</span> | <span class=lib25519>35645</span> | <span class=lib25519>103958</span> | <span class=lib25519>33935
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>31427</span> | <span class=lib25519>82614</span> | <span class=lib25519>62531</span> | <span class=lib25519>32282</span> | <span class=lib25519>35716</span> | <span class=lib25519>105701</span> | <span class=lib25519>33653
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>33451</span> | <span class=lib25519>89870</span> | <span class=lib25519>62812</span> | <span class=lib25519>34328</span> | <span class=lib25519>37793</span> | <span class=lib25519>116623</span> | <span class=lib25519>37975
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>32049</span> | <span class=s2n>83749</span> | | | | | |
| Intel Airmont (2015) | <span class=openssl>OpenSSL</span> | <span class=openssl>279700</span> | <span class=openssl>618989</span> | | <span class=openssl>292772</span> | <span class=openssl>277593</span> | <span class=openssl>853353</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>143379</span> | <span class=lib25519>449706</span> | <span class=lib25519>449742</span> | <span class=lib25519>147171</span> | <span class=lib25519>162917</span> | <span class=lib25519>539417</span> | <span class=lib25519>155486
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>143392</span> | <span class=lib25519>449634</span> | <span class=lib25519>449710</span> | <span class=lib25519>147073</span> | <span class=lib25519>162557</span> | <span class=lib25519>542105</span> | <span class=lib25519>155918
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>114744</span> | <span class=lib25519>421146</span> | <span class=lib25519>421219</span> | <span class=lib25519>118791</span> | <span class=lib25519>133576</span> | <span class=lib25519>503872</span> | <span class=lib25519>153471
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>114866</span> | <span class=lib25519>421207</span> | <span class=lib25519>421231</span> | <span class=lib25519>118408</span> | <span class=lib25519>134106</span> | <span class=lib25519>512588</span> | <span class=lib25519>153505
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>115717</span> | <span class=s2n>432248</span> | | | | | |
| Intel Broadwell (2014) | <span class=openssl>OpenSSL</span> | <span class=openssl>119594</span> | <span class=openssl>121170</span> | | <span class=openssl>122805</span> | <span class=openssl>119864</span> | <span class=openssl>389886</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>31437</span> | <span class=lib25519>93464</span> | <span class=lib25519>72452</span> | <span class=lib25519>32323</span> | <span class=lib25519>35905</span> | <span class=lib25519>122790</span> | <span class=lib25519>39757
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>28935</span> | <span class=lib25519>84915</span> | <span class=lib25519>74513</span> | <span class=lib25519>29754</span> | <span class=lib25519>33537</span> | <span class=lib25519>107474</span> | <span class=lib25519>33817
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>28994</span> | <span class=lib25519>84789</span> | <span class=lib25519>72117</span> | <span class=lib25519>29740</span> | <span class=lib25519>33541</span> | <span class=lib25519>106800</span> | <span class=lib25519>34289
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>31479</span> | <span class=lib25519>93366</span> | <span class=lib25519>72458</span> | <span class=lib25519>32244</span> | <span class=lib25519>36909</span> | <span class=lib25519>121430</span> | <span class=lib25519>39834
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>30752</span> | <span class=s2n>87489</span> | | | | | |
| Intel Haswell (2013) | <span class=openssl>OpenSSL</span> | <span class=openssl>125107</span> | <span class=openssl>163247</span> | | <span class=openssl>128058</span> | <span class=openssl>125087</span> | <span class=openssl>407784</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>45541</span> | <span class=lib25519>118265</span> | <span class=lib25519>76486</span> | <span class=lib25519>46374</span> | <span class=lib25519>50255</span> | <span class=lib25519>150229</span> | <span class=lib25519>50290
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>43488</span> | <span class=lib25519>115141</span> | <span class=lib25519>76684</span> | <span class=lib25519>44240</span> | <span class=lib25519>48268</span> | <span class=lib25519>152291</span> | <span class=lib25519>49855
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>43325</span> | <span class=lib25519>118224</span> | <span class=lib25519>76022</span> | <span class=lib25519>44084</span> | <span class=lib25519>47646</span> | <span class=lib25519>150462</span> | <span class=lib25519>50317
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>44780</span> | <span class=lib25519>119746</span> | <span class=lib25519>76395</span> | <span class=lib25519>45812</span> | <span class=lib25519>49606</span> | <span class=lib25519>152249</span> | <span class=lib25519>50732
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>47493</span> | <span class=s2n>154648</span> | | | | | |
| ARM Cortex-A53 (2012) | <span class=openssl>OpenSSL</span> | <span class=openssl>207910</span> | <span class=openssl>508113</span> | | <span class=openssl>215419</span> | <span class=openssl>198326</span> | <span class=openssl>550366</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>76118</span> | <span class=lib25519>141986</span> | <span class=lib25519>142046</span> | <span class=lib25519>77677</span> | <span class=lib25519>86313</span> | <span class=lib25519>313318</span> | <span class=lib25519>90121
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>75696</span> | <span class=lib25519>142140</span> | <span class=lib25519>142085</span> | <span class=lib25519>77510</span> | <span class=lib25519>86592</span> | <span class=lib25519>321606</span> | <span class=lib25519>90248
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>70959</span> | <span class=lib25519>137691</span> | <span class=lib25519>137752</span> | <span class=lib25519>72956</span> | <span class=lib25519>81821</span> | <span class=lib25519>318447</span> | <span class=lib25519>90308
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>71063</span> | <span class=lib25519>137686</span> | <span class=lib25519>137765</span> | <span class=lib25519>73198</span> | <span class=lib25519>81939</span> | <span class=lib25519>315368</span> | <span class=lib25519>90476
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>111524</span> | <span class=s2n>162789</span> | | | | | |
| Intel Core 2 (2006) | <span class=openssl>OpenSSL</span> | <span class=openssl>244742</span> | <span class=openssl>340071</span> | | <span class=openssl>251269</span> | <span class=openssl>238104</span> | <span class=openssl>723314</span> | |
| | <span class=lib25519>lib25519</span> | <span class=lib25519>99033</span> | <span class=lib25519>321976</span> | <span class=lib25519>320969</span> | <span class=lib25519>101551</span> | <span class=lib25519>109521</span> | <span class=lib25519>369918</span> | <span class=lib25519>106251
| | <span class=lib25519>lib25519+exp</span> | <span class=lib25519>99172</span> | <span class=lib25519>316731</span> | <span class=lib25519>316774</span> | <span class=lib25519>101260</span> | <span class=lib25519>109474</span> | <span class=lib25519>370317</span> | <span class=lib25519>105846
| | <span class=lib25519>lib25519+s2n+exp</span> | <span class=lib25519>77185</span> | <span class=lib25519>262935</span> | <span class=lib25519>263006</span> | <span class=lib25519>79237</span> | <span class=lib25519>87534</span> | <span class=lib25519>348480</span> | <span class=lib25519>105398
| | <span class=lib25519>lib25519+s2n</span> | <span class=lib25519>77151</span> | <span class=lib25519>262935</span> | <span class=lib25519>263009</span> | <span class=lib25519>79189</span> | <span class=lib25519>87219</span> | <span class=lib25519>349249</span> | <span class=lib25519>105126
| | <span class=s2n>s2n-bignum</span> | <span class=s2n>71164</span> | <span class=s2n>262728</span> | | | | | |


Microarchitectures are listed in reverse chronological order of when they were introduced.
Each library is assigned one foreground color in the table.

In the lib25519 distribution,
`command/lib25519-speed.c` measures lib25519;
`benchmarks/*-*` is the output of `lib25519-speed` on various machines;
`speedcomparison/openssl/*` has code to measure OpenSSL, and measurements from various machines;
`speedcomparison/s2n/*` has code to measure s2n-bignum, and measurements from various machines;
and `autogen/md-speed` extracts the table from those measurements.
OpenSSL benchmarks use version 4.0.1 (2026.06.09);
s2n-bignum benchmarks use commit fce78c7c17baee6a60511efe821930d4d049a6c0 (2026.06.12).

The table reports only interquartile means of cycle counts, not the full distribution of cycle counts.
See the full output files
for differences between multiple measurements and the interquartile mean.
The table reports the following major operations:

* "X key": Generating an X25519 public key and secret key.
    This is `dh_x25519_keypair selected 32` in the `lib25519-speed` output
    (`lib25519_dh_keypair` in the stable API).

    For s2n-bignum,
    this is `x25519-keygen` in the `s2n25519speed` output,
    measuring the cost of `curve25519_x25519base_byte_alt`,
    or `curve25519_x25519base_byte` on machines where that works and is faster.

    For OpenSSL,
    this is `x25519-keygen-main` in the `openssl25519speed` output,
    measuring the cost of `EVP_PKEY_Q_keygen(0,0,"X25519")`.
    This does not include small OpenSSL overheads for converting the public key and secret key to storage format.

* "X dh":
    Generating an X25519 shared secret.
    This is `dh_x25519 selected 32` in the `lib25519-speed` output
    (`lib25519_dh` in the stable API).

    For s2n-bignum,
    this is `x25519-dh` in the `s2n25519speed` output,
    measuring the cost of `curve25519_x25519_byte_alt`,
    or `curve25519_x25519_byte` on machines where that works and is faster.

    For OpenSSL,
    this is `x25519-dh-main` in the `openssl25519speed` output,
    measuring the cost of `EVP_PKEY_derive`
    (as in OpenSSL's speed-testing utility).
    This does not include the cost of `EVP_PKEY_new_raw_public_key`
    to decode the public key (`x25519-dh-pkdecode`, 2868 cycles on Tiger Lake),
    `EVP_PKEY_CTX_new` and `EVP_PKEY_derive_init` and `EVP_PKEY_derive_set_peer` for initialization
    (together `x25519-dh-init`, 1914 cycles on Tiger Lake),
    and 
    `EVP_PKEY_new_raw_private_key` to decode the secret key if it is not decoded already
    (`x25519-dh-skdecode`, 113904 cycles on Tiger Lake).

* "X batch":
    Cost _per secret_ of generating 16 separate shared secrets.
    This is `nPbatch_montgomery25519 selected 16` in the `lib25519-speed` output _divided by 16_.

* "Ed key": Generating an Ed25519 public key and secret key.
    This is `sign_ed25519_keypair selected 32` in the `lib25519-speed` output
    (`lib25519_sign_keypair` in the stable API).

    For OpenSSL,
    this is `ed25519-keygen-main` in the `openssl25519speed` output,
    measuring the cost of `EVP_PKEY_Q_keygen(0,0,"ED25519")`.
    This does not include small OpenSSL overheads for converting the public key and secret key to storage format.

* "Ed sign": Generating an Ed25519 signature of a 59-byte message.
    This is `sign_ed25519 selected 59` in the `lib25519-speed` output
    (`lib25519_sign` in the stable API).

    For OpenSSL,
    this is `ed25519-sign-main` in the `openssl25519speed` output,
    measuring the cost of `EVP_DigestSign`
    (as in OpenSSL's speed-testing utility).
    This does not include the cost of 
    `EVP_MD_CTX_new` and
    `EVP_DigestSignInit`
    (`ed25519-sign-init`, 2662 cycles on Tiger Lake),
    and `EVP_PKEY_new_raw_private_key` to decode the secret key if it is not decoded already
    (`ed25519-sign-skdecode`, 116227 cycles on Tiger Lake).

* "Ed verif": Verifying an Ed25519 signature and recovering a 59-byte message.
    This is `sign_ed25519_open selected 59` in the `lib25519-speed` output
    (`lib25519_sign_open` in the stable API).

    For OpenSSL,
    this is `ed25519-verify-main` in the `openssl25519speed` output,
    measuring the cost of `EVP_DigestVerify`
    (as in OpenSSL's speed-testing utility).
    This does not include the cost of 
    `EVP_MD_CTX_new` and
    `EVP_DigestVerifyInit`
    (together `ed25519-verify-init`, 2234 cycles on Tiger Lake),
    and `EVP_PKEY_new_raw_public_key`
    to decode the public key being used for verification
    (`ed25519-verify-pkdecode`, 3102 cycles on Tiger Lake).

* "Ed MSM": Cost _per point_ of multi-scalar multiplication with 16 points and 16 full-size scalars.
    This is `multiscalar_ed25519 selected 16` in the `lib25519-speed` output _divided by 16_.
