//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package proof

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"

	tt "github.com/coinbase/kryptology/internal"
	mod "github.com/coinbase/kryptology/pkg/core"
)

// To test ProveCompositeDL, the input must satisfy the following relationship
// P = 2Pi+1, Q = 2Qi+1, N = PQ
// H2 = H1^x mod N
// P, Q are 1024 bits.
func TestCdlProof(t *testing.T) {
	curve := btcec.S256()
	params := []*CdlProofParams{
		{
			Curve:   curve,
			Pi:      tt.B10("69979182966199119672351533979383654499397224507518060735584349051652764492448136547713282139549035562089101777193243018061896970048738918135727018564481835840179068003226387981023729616470203107028273690173680912153598953087314298633621289521741954003727691656981967430921179270576924304274459867142386866233"),
			Qi:      tt.B10("84424010159268042809195618234668170228427874149211682832595019116005334677981908011739260951914473600143292358100903745699777808120747187820649504013204732464439679512865842249450303793972825236153746944676836172054279530040675313001271469918167027979171285553816301512008832730050650239840859438662619111399"),
			N:       tt.B10("23631693014702686598491747297681569475877326460812464082819481422202713346211180070062414360449939288078360593861292547953001504075134774288233379964236347153126995445451429330749200073283458248684973345738352066279459449816118837062102541615816746664320639714285376717243575093782737364692876115029953880688277093224947831946660228299342362879622467185199611987459117940187846509287850536067217425664948192994941586900797272776595126412023378302307519372803612686581113206608355719746319871239226865149982986439036498029925509216269045641120927388902686667987841077785466791674964976428828991419580797672404965915133"),
			H1:      tt.B10("7946425901597611550738413402091207348349673201811011777758041950640367669127591562559941008463663269491315559897208768775232447391501592581877731140164059638274471726341875678455474107814193902512015507251883997545858299492500962124389479454741467013546908266057900991789262148766092771402882570705098310732185565230244188671537946720849813029966760353542287359829173490796747660692731745728903580183343647146866291218790289460250912792371107912019640755966623243965663097337215423829596916087566120282913217797405222525769972767463810191902348082642684555912203247043727191165051070774263967911353607952365245400947"),
			ScalarX: tt.B10("9060855727394538554280486019975466408154154373013627407948965978243783485406040771639015901954551816313856770333109273827682320951740510817356910069451842815860762800653008008734702455588363782662799763807936814615743776850798351473244971478097357831497231664301656006475400319088867810184234855807442006410165018848767142974822471227021406352580604137332089139556516988505126169997002017833858827496695461902663346560474857016062532738611411777646178283588990177506440466839975300743011477322819000458010731313375502203626231094265141803538312989410050792429290230188104355460623820692518310405901018793614779352365"),
			H2:      tt.B10("9655716947834799186539374175271253546360574889564941529186887148524811253942671582167482352632019351834566840338079786327815799490180732501072504891516646810008321428562261204389435547506173159604155572508109327801749630580463385051725499673777772465780243560444849344381658998224546017336909884296424486545406973413882945499464570750924583721544332515711367988346291270454498094198508290623057769669971189478287975093769597415578597441391516518992736837455435830471650960836487483840938880704655913775433524618584886395406891877498467764813222176205917831839824829752294548668410502170499760676452530462719513197659"),
		},
		{
			Curve:   curve,
			Pi:      tt.B10("67888050747812851425842238967480716528620751828903194145676972894251304673883735098328837590840818877762364813615848817532849830755892212636267607196610651447723752842688900061362287945644919469354026105141182996474829188730844136985148548346048734847454613613006744111959146944241178072643958108055109208669"),
			Qi:      tt.B10("74028583328840379462079789341032310086933613584606697607428537990913172909197902388422323870097092632268691549460498294185854606703100438377050619092037950146228310525692099718006602293395173980000397794576241083381416571186609861062015966780930151103765006974601121311197135038509984827174382833566361332459"),
			N:       tt.B10("20102624887268032436385352818309224611522117481187785072762969444240952373977012433059077411520297892283717463008349816277829183652055938423641934427094022881233221976429590801180822524846487163410907356244738306218466738291842021324571650500458383974369353051471917385538473367391737488963462364596813583268975946170601367819464693418426390466501882866808616688082647634542999240442063438027459804109064071267956138187461519377808857618462480066921719138950396485850908712512499459355024531358622117678159829573237832605918882277226089593396668852935983490680149025683860215703874267028152487275463608689386596630541"),
			H1:      tt.B10("2376518835100800976110377446508048627458382318670199614681941939618957469802074100964557196232832900256536094316139165206461461940284874993903911499340652135862549146228175201825717740466426272093870244464122393235976412050142856096926928069502460776404328490281063237799360068282994265687557447485328660684313615679759719396617374050181308075085809989635946482359863766907954463561844155574462370765003067298540057340699453379534447672507032661473128248596224981515811565065700663734038702396414461854756619095554520442820368266108115668333256283196813050455307108963605317668312367263714220550180930603737069042681"),
			ScalarX: tt.B10("14488423386509878470589768290899871750691012627125956350082287802110592303459003618093602404322350514916636961391783202847213112161591547267362064786324008087712203131139538157555973305762533116789572682662080915716282021431017132003226801582363966807205962239049864881081267891864101582031208944201226750450293268348489147631715204012459970983233418780535765088312679112283662704474419873686631944623889770749773996675154272528531861252719763116466349018521737163036477417936570219206390064706371039438309462010306171743504615466373920828843322740046857066875757090005851593014487741915608184497652830496479301046101"),
			H2:      tt.B10("15879604731069180823336489370430079158612574193637569666769343387116241501138672742037225999442092265612857660656553596930640898982694079345286033477972766098595684079264887219808793990685522553437704209214389414396934083563795665724990112792161324509368439824463260812389360700531646699291443828484023663984617896684393589265154610104646989442735621432109976922590169132245891501805740557524118742816342082961519552869452712799863985060370901800328292511999673878319215159254098261935327388754658587343367584404415707368858166863610846433431741855897776292306056157680786291582652749608898679384525696607905677562940"),
		},
		{
			Curve:   curve,
			Pi:      tt.B10("76330104306302336171080114522369103577528135517365964316288949628987850291369939487976722362743065903494105959054506903318328806931036907581609818174438335482939721074022473215585686298551052611871769430789160485977457333536557385501363802286842127881913680259737758668074492827574254852970687584896454490369"),
			Qi:      tt.B10("74680459525723769595192139188749594456005241009599674590157723679305006605114825831746447884821436868201575261183366679755987845338855141692678446759207587562380509454643686288880947446224009212779939349122453707965183148822196568163102099137040033736913880137247777891407945116122572996093120804287262887611"),
			N:       tt.B10("22801469060964340910128152680947327636805006778962251378289516834550134705056051838162503660322739730617028792712364262429554478015061929184008948187688156605464971916260293876377626719491351669108340778429763083516422879865468816939162564424003743741897912808344473692378164285592107193109403870333748874018903354200950300950333957718176868883093796762281239806732966028756450674690678269159740896623627493650760571188487210844131051548881955675140569772845035538976001671215032881856442978894225575234946453841339285439684649206855675243871163627152506578088434038260704484378510293449583782074426672839352750429797"),
			H1:      tt.B10("20806111194326574035679672768739736858091819757645346758021785460314376599301419996391552167503230068997416579785272226365650120077000964746008759656721174712277436474112550446553328239712665397967183925836893294379889458489429334367827089024323487828041759547979283434655829287281438497101362147499106999452268149455783225328882973374880831689906754199016227640168040507681655515611153025357280494053341572862736455523226702405927614126963630370765902600152731846620871866239702506880141644695257384096428760156930215724940913719081038961766230182718949910447613483603623677539012295395768844645520397810463957385064"),
			ScalarX: tt.B10("15680711572265412302063710770100256379142303758183622454827770633536053015410125301746669617168927840582543443640485515259880553994650563353596050406993218267888689674576174291292544181319318290540656134509455403555836349380843917576044782017032252612309396418725437217288341460444014546130837821402423422015544908647599204304517283721877733784155111971303558627174554499877650796086982127066231644058631024937179283400939543733407645999366471982125969899025962517640974247501614047650918073386577048332793677704293299537593243143375588086886366242986351992009685208447912923549964467532904719505360890187205305699459"),
			H2:      tt.B10("622658591279147036927766482179620016370160116224103009000775777741977746076069841974182622264916996020211240564452627583018818598398927997509249354168351328209433205510046968758622632579900996917482688488998451832822212978905701352270659049839671444956557784505017848150403230178964425529347380297488762918345919142437261093899029818695107925965006069381608544120388500753110329923373348736800348712931341066415725312620621446928469239018646863379711766363968549027231209938338940192298373744505449601807104666477538150562655076590620733447959977455361655346656264899909425757426204005449809320724302574761557419731"),
		},
		{
			Curve:   curve,
			Pi:      tt.B10("82883554749339666963586441494337620435893416497294374579482883836972805943324488477506490102969223378939443091658227508760650417478882372581176762787634196217793921803806235447860770523627208770135378072841065094614012362146856770210350489621870309656243783617131413009270202064367777187073091174042668140719"),
			Qi:      tt.B10("69225815559898813841972197257369214418510039477259267562386576754105996517641287187354271185517091465322957847668322767001848636388632130892875166130086418905967220151161781954791233039810992082584155593127502090379734391611013337128628560799387768620268946450680104840369217258842944810825920588121700493123"),
			N:       tt.B10("22950726696106252594177150043702726168157075733848228603840197369993285323355022881679851977892612224492713729744126629955665066185266969130231247332745420728832293954467828637032990587597267170802253468024344651848441930746397341359174394464185978358597098005624864548609773709166088442852948437798183551200690008139352012083637986045796225151454930178660324726916856513773213004410369292488865134255536689323311258239790555126688842073858461480933636320357175937577130089085815509252853603516538213035830991253353875279132119189820404992281851244229733861968450581391216339219701593104607616741537835284904160369433"),
			H1:      tt.B10("16947714733355968353285087150980488488797136017640333340847024527191500632540085135174374838838715006487240699680849864319988293467608752442017432880375482280049463974990082250738962509544799109260352673773363020130912159245439261485567779683327978891270641219826411739866109659592983663828776367898959223055923734598751887123852213233896336740080689174821591168670844378375591715457972908784654711637529831964663980121859709144936543716417104012030317467473498694302940867353074810598697963868975995075238602465887766432955803284002304692712238697582306243591149618478337706345348084669052787889594825614138884254857"),
			ScalarX: tt.B10("7141254243649730791870594504444361694661965691954862970497207011721889507031355783622099741060773071546652817450619360631529113879924641192639273248901801434686465102669717633914711151251701245166721810172824415155507752247435419525086338189605111924764954431194140203170189796624665041965605014805810747231699659835664794666132438293568877475559274697866641060695899446664193994146827881518532054761256829920204913452337762833840277415230500040020938819338025433474821575450449377841822597092548025041637670944198465638103484247157760932440805627816356173686151826558462387115649657392225680106913427091008986414122"),
			H2:      tt.B10("8866059999511505016265292876826970660608930702174554980770241858104175572432348371991218071753504427593404759665569189913263950749226807497981103036201156716522101847506433897179982772552762029382294277009511885974503187408175951461864212501193897223537353833041834349069832240822300902557558570805521547512377574784899720538802689603248450763304879728986861357544735140736494322201689579228336939649023190017663290242463120794168012436767474812418152518586579869344956732872664353467783350156896625854233546860497073584838622854905571366278592478526806298651643691717520658141804698488684958703838336892275534751751"),
		},
	}

	for _, pp := range params {
		proof, err := pp.Prove()
		if err != nil {
			t.Errorf("CdlProve failed: #{err}")
		}
		cv := &CdlVerifyParams{
			Curve: curve,
			H1:    pp.H1,
			H2:    pp.H2,
			N:     pp.N,
		}
		err = proof.Verify(cv)
		require.NoError(t, err)
	}
}

func TestCdlProofTampered(t *testing.T) {
	curve := btcec.S256()
	params := []*CdlProofParams{
		{
			Curve:   curve,
			Pi:      tt.B10("69979182966199119672351533979383654499397224507518060735584349051652764492448136547713282139549035562089101777193243018061896970048738918135727018564481835840179068003226387981023729616470203107028273690173680912153598953087314298633621289521741954003727691656981967430921179270576924304274459867142386866233"),
			Qi:      tt.B10("84424010159268042809195618234668170228427874149211682832595019116005334677981908011739260951914473600143292358100903745699777808120747187820649504013204732464439679512865842249450303793972825236153746944676836172054279530040675313001271469918167027979171285553816301512008832730050650239840859438662619111399"),
			N:       tt.B10("23631693014702686598491747297681569475877326460812464082819481422202713346211180070062414360449939288078360593861292547953001504075134774288233379964236347153126995445451429330749200073283458248684973345738352066279459449816118837062102541615816746664320639714285376717243575093782737364692876115029953880688277093224947831946660228299342362879622467185199611987459117940187846509287850536067217425664948192994941586900797272776595126412023378302307519372803612686581113206608355719746319871239226865149982986439036498029925509216269045641120927388902686667987841077785466791674964976428828991419580797672404965915133"),
			H1:      tt.B10("7946425901597611550738413402091207348349673201811011777758041950640367669127591562559941008463663269491315559897208768775232447391501592581877731140164059638274471726341875678455474107814193902512015507251883997545858299492500962124389479454741467013546908266057900991789262148766092771402882570705098310732185565230244188671537946720849813029966760353542287359829173490796747660692731745728903580183343647146866291218790289460250912792371107912019640755966623243965663097337215423829596916087566120282913217797405222525769972767463810191902348082642684555912203247043727191165051070774263967911353607952365245400947"),
			ScalarX: tt.B10("9060855727394538554280486019975466408154154373013627407948965978243783485406040771639015901954551816313856770333109273827682320951740510817356910069451842815860762800653008008734702455588363782662799763807936814615743776850798351473244971478097357831497231664301656006475400319088867810184234855807442006410165018848767142974822471227021406352580604137332089139556516988505126169997002017833858827496695461902663346560474857016062532738611411777646178283588990177506440466839975300743011477322819000458010731313375502203626231094265141803538312989410050792429290230188104355460623820692518310405901018793614779352365"),
			H2:      tt.B10("9655716947834799186539374175271253546360574889564941529186887148524811253942671582167482352632019351834566840338079786327815799490180732501072504891516646810008321428562261204389435547506173159604155572508109327801749630580463385051725499673777772465780243560444849344381658998224546017336909884296424486545406973413882945499464570750924583721544332515711367988346291270454498094198508290623057769669971189478287975093769597415578597441391516518992736837455435830471650960836487483840938880704655913775433524618584886395406891877498467764813222176205917831839824829752294548668410502170499760676452530462719513197659"),
		},
		{
			Curve:   curve,
			Pi:      tt.B10("67888050747812851425842238967480716528620751828903194145676972894251304673883735098328837590840818877762364813615848817532849830755892212636267607196610651447723752842688900061362287945644919469354026105141182996474829188730844136985148548346048734847454613613006744111959146944241178072643958108055109208669"),
			Qi:      tt.B10("74028583328840379462079789341032310086933613584606697607428537990913172909197902388422323870097092632268691549460498294185854606703100438377050619092037950146228310525692099718006602293395173980000397794576241083381416571186609861062015966780930151103765006974601121311197135038509984827174382833566361332459"),
			N:       tt.B10("20102624887268032436385352818309224611522117481187785072762969444240952373977012433059077411520297892283717463008349816277829183652055938423641934427094022881233221976429590801180822524846487163410907356244738306218466738291842021324571650500458383974369353051471917385538473367391737488963462364596813583268975946170601367819464693418426390466501882866808616688082647634542999240442063438027459804109064071267956138187461519377808857618462480066921719138950396485850908712512499459355024531358622117678159829573237832605918882277226089593396668852935983490680149025683860215703874267028152487275463608689386596630541"),
			H1:      tt.B10("2376518835100800976110377446508048627458382318670199614681941939618957469802074100964557196232832900256536094316139165206461461940284874993903911499340652135862549146228175201825717740466426272093870244464122393235976412050142856096926928069502460776404328490281063237799360068282994265687557447485328660684313615679759719396617374050181308075085809989635946482359863766907954463561844155574462370765003067298540057340699453379534447672507032661473128248596224981515811565065700663734038702396414461854756619095554520442820368266108115668333256283196813050455307108963605317668312367263714220550180930603737069042681"),
			ScalarX: tt.B10("14488423386509878470589768290899871750691012627125956350082287802110592303459003618093602404322350514916636961391783202847213112161591547267362064786324008087712203131139538157555973305762533116789572682662080915716282021431017132003226801582363966807205962239049864881081267891864101582031208944201226750450293268348489147631715204012459970983233418780535765088312679112283662704474419873686631944623889770749773996675154272528531861252719763116466349018521737163036477417936570219206390064706371039438309462010306171743504615466373920828843322740046857066875757090005851593014487741915608184497652830496479301046101"),
			H2:      tt.B10("15879604731069180823336489370430079158612574193637569666769343387116241501138672742037225999442092265612857660656553596930640898982694079345286033477972766098595684079264887219808793990685522553437704209214389414396934083563795665724990112792161324509368439824463260812389360700531646699291443828484023663984617896684393589265154610104646989442735621432109976922590169132245891501805740557524118742816342082961519552869452712799863985060370901800328292511999673878319215159254098261935327388754658587343367584404415707368858166863610846433431741855897776292306056157680786291582652749608898679384525696607905677562940"),
		},
		{
			Curve:   curve,
			Pi:      tt.B10("76330104306302336171080114522369103577528135517365964316288949628987850291369939487976722362743065903494105959054506903318328806931036907581609818174438335482939721074022473215585686298551052611871769430789160485977457333536557385501363802286842127881913680259737758668074492827574254852970687584896454490369"),
			Qi:      tt.B10("74680459525723769595192139188749594456005241009599674590157723679305006605114825831746447884821436868201575261183366679755987845338855141692678446759207587562380509454643686288880947446224009212779939349122453707965183148822196568163102099137040033736913880137247777891407945116122572996093120804287262887611"),
			N:       tt.B10("22801469060964340910128152680947327636805006778962251378289516834550134705056051838162503660322739730617028792712364262429554478015061929184008948187688156605464971916260293876377626719491351669108340778429763083516422879865468816939162564424003743741897912808344473692378164285592107193109403870333748874018903354200950300950333957718176868883093796762281239806732966028756450674690678269159740896623627493650760571188487210844131051548881955675140569772845035538976001671215032881856442978894225575234946453841339285439684649206855675243871163627152506578088434038260704484378510293449583782074426672839352750429797"),
			H1:      tt.B10("20806111194326574035679672768739736858091819757645346758021785460314376599301419996391552167503230068997416579785272226365650120077000964746008759656721174712277436474112550446553328239712665397967183925836893294379889458489429334367827089024323487828041759547979283434655829287281438497101362147499106999452268149455783225328882973374880831689906754199016227640168040507681655515611153025357280494053341572862736455523226702405927614126963630370765902600152731846620871866239702506880141644695257384096428760156930215724940913719081038961766230182718949910447613483603623677539012295395768844645520397810463957385064"),
			ScalarX: tt.B10("15680711572265412302063710770100256379142303758183622454827770633536053015410125301746669617168927840582543443640485515259880553994650563353596050406993218267888689674576174291292544181319318290540656134509455403555836349380843917576044782017032252612309396418725437217288341460444014546130837821402423422015544908647599204304517283721877733784155111971303558627174554499877650796086982127066231644058631024937179283400939543733407645999366471982125969899025962517640974247501614047650918073386577048332793677704293299537593243143375588086886366242986351992009685208447912923549964467532904719505360890187205305699459"),
			H2:      tt.B10("622658591279147036927766482179620016370160116224103009000775777741977746076069841974182622264916996020211240564452627583018818598398927997509249354168351328209433205510046968758622632579900996917482688488998451832822212978905701352270659049839671444956557784505017848150403230178964425529347380297488762918345919142437261093899029818695107925965006069381608544120388500753110329923373348736800348712931341066415725312620621446928469239018646863379711766363968549027231209938338940192298373744505449601807104666477538150562655076590620733447959977455361655346656264899909425757426204005449809320724302574761557419731"),
		},
		{
			Curve:   curve,
			Pi:      tt.B10("82883554749339666963586441494337620435893416497294374579482883836972805943324488477506490102969223378939443091658227508760650417478882372581176762787634196217793921803806235447860770523627208770135378072841065094614012362146856770210350489621870309656243783617131413009270202064367777187073091174042668140719"),
			Qi:      tt.B10("69225815559898813841972197257369214418510039477259267562386576754105996517641287187354271185517091465322957847668322767001848636388632130892875166130086418905967220151161781954791233039810992082584155593127502090379734391611013337128628560799387768620268946450680104840369217258842944810825920588121700493123"),
			N:       tt.B10("22950726696106252594177150043702726168157075733848228603840197369993285323355022881679851977892612224492713729744126629955665066185266969130231247332745420728832293954467828637032990587597267170802253468024344651848441930746397341359174394464185978358597098005624864548609773709166088442852948437798183551200690008139352012083637986045796225151454930178660324726916856513773213004410369292488865134255536689323311258239790555126688842073858461480933636320357175937577130089085815509252853603516538213035830991253353875279132119189820404992281851244229733861968450581391216339219701593104607616741537835284904160369433"),
			H1:      tt.B10("16947714733355968353285087150980488488797136017640333340847024527191500632540085135174374838838715006487240699680849864319988293467608752442017432880375482280049463974990082250738962509544799109260352673773363020130912159245439261485567779683327978891270641219826411739866109659592983663828776367898959223055923734598751887123852213233896336740080689174821591168670844378375591715457972908784654711637529831964663980121859709144936543716417104012030317467473498694302940867353074810598697963868975995075238602465887766432955803284002304692712238697582306243591149618478337706345348084669052787889594825614138884254857"),
			ScalarX: tt.B10("7141254243649730791870594504444361694661965691954862970497207011721889507031355783622099741060773071546652817450619360631529113879924641192639273248901801434686465102669717633914711151251701245166721810172824415155507752247435419525086338189605111924764954431194140203170189796624665041965605014805810747231699659835664794666132438293568877475559274697866641060695899446664193994146827881518532054761256829920204913452337762833840277415230500040020938819338025433474821575450449377841822597092548025041637670944198465638103484247157760932440805627816356173686151826558462387115649657392225680106913427091008986414122"),
			H2:      tt.B10("8866059999511505016265292876826970660608930702174554980770241858104175572432348371991218071753504427593404759665569189913263950749226807497981103036201156716522101847506433897179982772552762029382294277009511885974503187408175951461864212501193897223537353833041834349069832240822300902557558570805521547512377574784899720538802689603248450763304879728986861357544735140736494322201689579228336939649023190017663290242463120794168012436767474812418152518586579869344956732872664353467783350156896625854233546860497073584838622854905571366278592478526806298651643691717520658141804698488684958703838336892275534751751"),
		},
	}

	for _, pp := range params {
		proof, err := pp.Prove()
		if err != nil {
			t.Errorf("ProveCompositeDL failed: #{err}")
		}
		cv := &CdlVerifyParams{
			Curve: curve,
			H1:    pp.H1,
			H2:    pp.H2,
			N:     pp.N,
		}

		proof.u[0].Add(proof.u[0], mod.One)
		if err := proof.Verify(cv); err == nil {
			t.Errorf("Expected CdlVerify to fail but succeeded")
		}

		proof.s[0].Add(proof.s[0], mod.One)
		if err := proof.Verify(cv); err == nil {
			t.Errorf("Expected CdlVerify to fail but succeeded")
		}

		proof.u[0].Sub(proof.u[0], mod.One)
		proof.s[0].Sub(proof.s[0], mod.One)
		cv.H1.Add(cv.H1, mod.One).Mod(cv.H1, cv.N)
		if err := proof.Verify(cv); err == nil {
			t.Errorf("Expected CdlVerify to fail but succeeded")
		}

		cv.H2.Add(cv.H2, mod.One).Mod(cv.H2, cv.N)
		if err := proof.Verify(cv); err == nil {
			t.Errorf("Expected CdlVerify to fail but succeeded")
		}
	}
}

// Recall that if the input to ProveCompositeDL is correct, h2 must be equal to h1^alpha
// In this test, we set h1, h2, alpha as random values purposely, which should make the verification incorrect.
// Pi, Qi and N are generated correctly via a side program and P = 2*Pi+1, Q=2*Qi+1, N = PQ.
func TestCdlProofRandValues(t *testing.T) {
	curve := btcec.S256()
	pi := tt.B10("69194751040870458870606183726555435909086788535387699389669514131170791430457074867750473589740101538563709151356299341625165252163443101897409551452286117584229969813571483217371266470819768503264181903858655002445121864855018050830086220605407845379111572386400613256577806622758645652928390261158201056559")
	qi := tt.B10("82637633161541176464703465424481086073529001916957361226495184953100155149539385427685606853188505515091549850006242891763636582655438360592297819967249750168526728829169019442914966932888398845776455389981984845838757231468840109235034665375458310070782153041383978515298908502237439774363022952285938551943")
	n := tt.B10("22872361812878489876060907543278948578387147675520825541510527859532146822027982754603729909037595317258111424852220535313592335395829235521522221441210174887876906980298605562656860093862386445954521521259318033327437806280309919241306055629653903861746476630826350344558570927747295219571966411822552470277193572834840982644421834542817903768311471107148331859193087484753051900698022956193382070220395102397179763375245079349836869922078435771068117889295943356668151757001536241849212462656770832021260539449326135398784589973524619988879740444034914415022192221461822737062898569969299902763089827704220688593553")
	h1, _ := mod.Rand(n)
	alpha, _ := mod.Rand(new(big.Int).Mul(pi, qi))
	h2, _ := mod.Rand(n)
	params := []*CdlProofParams{
		{
			Curve:   curve,
			Pi:      pi,
			Qi:      qi,
			H1:      h1,
			H2:      h2,
			ScalarX: alpha,
			N:       n,
		},
	}

	for _, pp := range params {
		proof, err := pp.Prove()
		if err != nil {
			t.Errorf("CdlProve failed: #{err}")
		}
		cv := &CdlVerifyParams{
			Curve: curve,
			H1:    pp.H1,
			H2:    pp.H2,
			N:     pp.N,
		}
		err = proof.Verify(cv)
		require.Error(t, err)
	}
}

func TestCdlProofInvalidParams(t *testing.T) {
	params := CdlProofParams{}
	if _, err := params.Prove(); err == nil {
		t.Errorf("CdlProve succeeded but should've failed")
	}

	curve := btcec.S256()
	P := tt.B10("165767109498679333927172882988675240871786832994588749158965767673945611886648976955012980205938446757878886183316455017521300834957764745162353525575268392435587843607612470895721541047254417540270756145682130189228024724293713540420700979243740619312487567234262826018540404128735554374146182348085336281439")
	Q := tt.B10("138451631119797627683944394514738428837020078954518535124773153508211993035282574374708542371034182930645915695336645534003697272777264261785750332260172837811934440302323563909582466079621984165168311186255004180759468783222026674257257121598775537240537892901360209680738434517685889621651841176243400986247")
	pi := new(big.Int).Div(new(big.Int).Sub(P, big.NewInt(1)), big.NewInt(2))
	qi := new(big.Int).Div(new(big.Int).Sub(Q, big.NewInt(1)), big.NewInt(2))
	n := new(big.Int).Mul(P, Q)
	h1, _ := mod.Rand(n)
	alpha, _ := mod.Rand(n)
	h2 := new(big.Int).Exp(h1, alpha, n)
	params = CdlProofParams{
		Curve:   curve,
		Pi:      pi,
		Qi:      qi,
		H1:      h1,
		H2:      h2,
		ScalarX: alpha,
		N:       n,
	}
	proof, _ := params.Prove()
	cv := &CdlVerifyParams{}
	if err := proof.Verify(cv); err == nil {
		t.Errorf("CdlVerify succeeded but should've failed.")
	}

	cv.Curve = params.Curve
	if err := proof.Verify(cv); err == nil {
		t.Errorf("CdlVerify succeeded but should've failed")
	}

	cv.H1 = params.H1
	if err := proof.Verify(cv); err == nil {
		t.Errorf("CdlVerify succeeded but should've failed")
	}

	cv.N = params.N
	if err := proof.Verify(cv); err == nil {
		t.Errorf("CdlVerify succeeded but should've failed")
	}
}

// Numbers in array u and s are randomly generated via a side program.
func TestMarshalJsonCdlProof(t *testing.T) {
	test := CdlProof{
		u: []*big.Int{
			bi(31), bi(38), bi(77), bi(43), bi(27),
			bi(42), bi(56), bi(36), bi(45), bi(20),
			bi(81), bi(31), bi(69), bi(36), bi(35),
			bi(47), bi(44), bi(95), bi(95), bi(79),
			bi(90), bi(67), bi(90), bi(95), bi(96),
			bi(73), bi(100), bi(17), bi(26), bi(56),
			bi(96), bi(66), bi(63), bi(31), bi(12),
			bi(91), bi(96), bi(83), bi(89), bi(34),
			bi(91), bi(54), bi(66), bi(46), bi(19),
			bi(50), bi(30), bi(32), bi(74), bi(17),
			bi(98), bi(98), bi(56), bi(33), bi(57),
			bi(55), bi(98), bi(73), bi(31), bi(95),
			bi(31), bi(26), bi(45), bi(42), bi(59),
			bi(70), bi(30), bi(10), bi(58), bi(59),
			bi(47), bi(35), bi(35), bi(74), bi(73),
			bi(74), bi(38), bi(95), bi(99), bi(12),
			bi(34), bi(40), bi(64), bi(22), bi(30),
			bi(31), bi(81), bi(56), bi(20), bi(58),
			bi(26), bi(16), bi(31), bi(83), bi(29),
			bi(13), bi(20), bi(29), bi(37), bi(92),
			bi(10), bi(12), bi(24), bi(15), bi(34),
			bi(79), bi(54), bi(59), bi(40), bi(18),
			bi(88), bi(70), bi(10), bi(81), bi(11),
			bi(13), bi(81), bi(10), bi(66), bi(15),
			bi(23), bi(39), bi(92), bi(32), bi(78),
			bi(96), bi(72), bi(23),
		},
		s: []*big.Int{
			bi(58), bi(85), bi(46), bi(71), bi(67),
			bi(64), bi(15), bi(98), bi(47), bi(22),
			bi(82), bi(26), bi(40), bi(76), bi(74),
			bi(15), bi(66), bi(88), bi(77), bi(85),
			bi(69), bi(18), bi(56), bi(58), bi(16),
			bi(21), bi(46), bi(61), bi(97), bi(42),
			bi(85), bi(83), bi(21), bi(69), bi(75),
			bi(22), bi(97), bi(41), bi(33), bi(75),
			bi(21), bi(11), bi(15), bi(59), bi(12),
			bi(21), bi(45), bi(63), bi(94), bi(79),
			bi(47), bi(92), bi(11), bi(27), bi(77),
			bi(63), bi(50), bi(25), bi(100), bi(25),
			bi(48), bi(70), bi(98), bi(26), bi(99),
			bi(75), bi(23), bi(61), bi(15), bi(23),
			bi(36), bi(86), bi(73), bi(71), bi(88),
			bi(38), bi(91), bi(89), bi(65), bi(68),
			bi(78), bi(23), bi(73), bi(84), bi(71),
			bi(90), bi(17), bi(13), bi(15), bi(40),
			bi(49), bi(79), bi(45), bi(40), bi(84),
			bi(71), bi(50), bi(40), bi(16), bi(94),
			bi(88), bi(95), bi(77), bi(87), bi(49),
			bi(62), bi(38), bi(28), bi(20), bi(68),
			bi(31), bi(87), bi(98), bi(67), bi(91),
			bi(62), bi(60), bi(91), bi(71), bi(25),
			bi(44), bi(72), bi(43), bi(19), bi(65),
			bi(24), bi(16), bi(47),
		},
	}

	testJSON, err := json.Marshal(test)
	require.NoError(t, err)
	require.NotNil(t, testJSON)

	unmarshaled := new(CdlProof)
	err = json.Unmarshal(testJSON, unmarshaled)
	require.NoError(t, err)

	require.Equal(t, test.u, unmarshaled.u)
	require.Equal(t, test.s, unmarshaled.s)
}

// Set SafePrimes P, Q to 100-bit length instead of 1024-bit length to test small modulus.
// P and Q are generated using the SafePrime Generator via side program
// P = 1028783406134480509185302717063
// Q = 1093599917998934718101903070203.
func TestSmallModulus(t *testing.T) {
	curve := btcec.S256()
	pi := tt.B10("514391703067240254592651358531")
	qi := tt.B10("546799958999467359050951535101")
	n := tt.B10("1125077448587332637478027734178491491371406782346677534973789")
	h1 := tt.B10("1044115315550618597679290143551713476694466276523205398373512")
	x := tt.B10("232563802391440426149543743017793250842498595895226805619115")
	h2 := tt.B10("47869393962942536914052882363726168408056214230151183601468")
	params := []*CdlProofParams{
		{
			Curve:   curve,
			Pi:      pi,
			Qi:      qi,
			H1:      h1,
			H2:      h2,
			ScalarX: x,
			N:       n,
		},
	}

	for _, pp := range params {
		proof, err := pp.Prove()
		if err != nil {
			t.Errorf("CdlProve failed: #{err}")
		}
		cv := &CdlVerifyParams{
			Curve: curve,
			H1:    pp.H1,
			H2:    pp.H2,
			N:     pp.N,
		}
		err = proof.Verify(cv)
		if err == nil {
			t.Errorf("CdlVerify should fail but succeeded")
		}
	}
}
