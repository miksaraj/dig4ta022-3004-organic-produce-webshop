export const state = () => ({
	list: [
		{
			id: 1,
			header: 'Mitä ihmettä on psykologia',
			text: [
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo.'
				},
				{
					type: 'ul',
					content: [
						'Miksi ihmiset valitsevat mieluiten tyhjän penkin metrossa?',
						'Miksi jotkut lannistuvat ja toiset innostuvat samanlaisista tehtävistä?',
						'Miksi ihmiset ärtyvät ruuhkassa?'
					]
				},
				{
					type: 'p',
					content:
						'Psykologia on tieteenala, jossa tarkastellaan ihmisen toimintaa. Sen avulla opiskelija oppii tuntemaan itseään sekä saa välineitä muiden ymmärtämiseen. Keskeinen teema kurssilla on oppiminen.  "Miten oppisin paremmin?" Kurssilla tätä kysymystä tutkitaan psykologian avulla.'
				},
				{
					type: 'p',
					content:
						'Oppimateriaalin ovat kirjoittaneet Teija Havana, teija.havana@eduvantaa.fi (0445813353) sekä Markus Masalin, markus.masalin@eduvantaa.fi (040 7684221). '
				}
			]
		},
		{
			id: 2,
			header: 'Tehtävä:',
			description:
				'Mitä tiedät psykologiasta ennen tätä kurssia? Millaista se on?',
			placeholder: 'Kirjoita tähän...'
		},
		{
			id: 3,
			header: 'Kurssin sisältö',
			text: [
				{
					type: 'p',
					content:
						'Tällä psykologian johdantokurssilla tutustutaan psykologian keskeisiin käsitteisiin ja teorioihin. '
				},
				{
					type: 'p',
					content:
						'Psykologia on tieteenala, jossa tarkastellaan ihmisen toimintaa. Sen avulla opiskelija oppii tuntemaan itseään sekä saa välineitä muiden ymmärtämiseen. Keskeinen teema kurssilla on oppiminen.  "Miten oppisin paremmin?" Kurssilla tätä kysymystä tutkitaan psykologian avulla.'
				},
				{
					type: 'ul',
					content: [
						'Biologinen: Luvussa 2 tutkitaan ihmistä biologisena olentona ja miten keho, aivot ja hermosto vaikuttavat ajatuksiin ja tunteisiin.',
						'Käyttäytyminen: Luvussa 3 matkustetaan ajassa 100 vuotta taaksepäin, ja tutustutaan behavioristeihin, joiden tavoitteena oli saada psykologia tieteellisemmälle pohjalle eläinkokeiden avulla.',
						'Kognitiivinen: Luvussa 4 perehdytään ihmisen tiedonkäsittelyjärjestelmään. Kognitiivisen psykologian tutkijat oivalsivat, että ihminen ei ole passiivinen sätkynukke, jonka käyttäytymistä voisi täysin manipuoloida. Kognitiviisen psykologian tutkimukset osoittivat, että ihminen on aktiivinen tiedonrakentaja.',
						'Tunteet ja motivaatio: luvussa 5 syvennytään siihen, mikä saa ihmisen toimimaan, syttymään ja innostumaan. Kolikon kääntöpuolena on tosin se, että samat tekijät saavat ihmisen lukkoon, luovuttamaan ja alistumaan.',
						'Sosiokulttuurinen: luvussa 6 on aiheena ihmisen sosiaalinen ympäristö, mikä avulla ihminen pystyy oppimaan nopeasti, mutta kohdistaa häneen suuria odotuksia ja paineita.',
						'Psykologinen tutkimus: viimeisessä luvussa keskitymme psykologiseen tutkimukseen.'
					]
				},
				{
					type: 'p',
					content:
						'Oppimateriaalin ovat kirjoittaneet Teija Havana, teija.havana@eduvantaa.fi (0445813353) sekä Markus Masalin, markus.masalin@eduvantaa.fi (040 7684221). '
				}
			]
		},
		{
			id: 4,
			header: 'Psykologinen tieto ja arkitieto',
			text: [
				{
					type: 'p',
					content:
						'Ihmiset tekevät usein havaintoja muiden ja omasta toiminnasta. Näistä havainnosta voidaan käyttää käsitettä arkitieto. Arkitietoa on sellainen tieto, joka perustuu omaan kokemukseen tai  yleisiin uskomuksiin. Esimerkkinä tällaisesta yleisestä uskomuksesta on ajatus, että silmälasipäiset ihmiset ovat älykkäitä. Olet ehkä kerran tavannut ihmisen henkilön, jolla on silmälasit ja hän on älykäs.  Arkitietoa on ajatella, että silmälasit tekevät ihmisestä älykkään. Arkitieto ei ole luotettavaa, se ei aina pidä paikkaansa. '
				},
				{
					type: 'p',
					content:
						'Tieteellinen tieto on tietoa, joka perustuu tutkimuksiin. Tieteellinen tieto voi kyseenalaistaa meidän monet arkiset uskomukset, kuten esimerkiksi silmälasien ja älykkyyden välisestä yhteydestä. Tieteellisen tiedon kerääminen vie aikaa, se on hidasta ja se vaatii johdonmukaista tiedon testaamista.'
				},
				{
					type: 'p',
					content: 'Tieteellisellä tiedolla on useita kriteerejä. :'
				},
				{
					type: 'ul',
					content: [
						'Tieteellisen tiedon tulee olla <strong>testattavaa</strong> eli aiheesta pitää olla sellainen, josta voidaan kerätä tietoa. ',
						'Tieteellinen tieto on <strong>objektiivista</strong> eli puolueetonta. Tutkijan tulee säilyttää puolueeton asenne aiheeseensa koko tutkimuksen ajan. Hänen omien mielipiteiden tai asenteiden ei tule vaikuttaa tutkimustuloksiin. ',
						'Tieteellisen tiedon tulisi olla myös <strong>yleistettävissä</strong>. Tutkija on esimerkiksi kerännyt tietoa jostain aiheesta tutkimalla kymmeniä koehenkilöitä. Tämä koehenkilöiden porukka on nimeltään otos. Yleistettävyys tarkoittaa sitä, että tieto tulisi voida yleistää myös otoksen ulkopuolelle eli laajempaankin ihmisryhmään. ',
						'Tieteellinen tieto on <strong>julkista</strong>. Tutkimus julkaistaan tiedeyhteisön arvioitavaksi, jotta sen heikkouksista ja vahvuuksista voidaan keskustella',
						'Tieteen tekemisessä on vielä huomioitava <strong>toistettavuus </strong>. Toistettavuus tarkoittaa sitä, että tutkimus tulisi pystyä toistamaan uudelleen siten, että tutkimustulokset pysyvät samoina. ',
						'Viimeisenä tieteen kriteerinä on <strong>itseään korjaavuus</strong>, joka tarkoittaa sitä, että uusi tutkimus aina tarkentaa ja täsmentää jo olemassa olevia teorioita, tutkijan tavoitteena ei ole tutkimuksella tarjota täysin valmista ja lopullista tietoa vaan ymmärtää taas tutkittavaa ilmiötä paremmin.'
					]
				}
			]
		},
		{
			id: 5,
			header: 'Aivot ja hermostuminen',
			text: [
				{
					type: 'p',
					content:
						'Ihmisen aivot painavat noin 1,5 kg. Ne rakentuvat yli 80 miljardista hermosolusta ja niiden välisistä yhteyksistä. Ihmisen aivot voidaan jakaa sisempiin osiin ja aivojen kuorikerrokseen. Aivojen kuorikerros on ihmisillä suurempi kuin muilla nisäkkäillä, erityisesti kuorikerroksen etuosa eli otsalohko on ihmisillä erityisen kehittynyt. Aivokuori on siten aivojen uudempia osia. Aivokuori on tärkeä esimerkiksi aistihavaintojen, ajattelun sekä toiminnan säätelyn kannalta. Eli aivokuoren toimintaa tarvitaan älykkääseen toimintaan.'
				},
				{
					type: 'p',
					content:
						'Tässä on kuva aivojen aivokuoresta. Eri väreillä on selitetty aivokuoren toimintaa. '
				},
				{
					type: 'ul',
					content: [
						'Vihreä väri: näköaistiin liittyvän tiedon käsittely takaraivolohkossa.',
						'Sininen väri: tuntoaistiin liittyvän tiedon käsittely päälakilohkossa',
						'Keltainen: kuuloaistiin liittyvän tiedon käsittely ohimolohkossa.',
						'Vaaleanpunainen: liikkeeseen liittyvän tiedon käsittely otsalohkossa'
					]
				},
				{
					type: 'img',
					content:
						'/img/Blausen_0102_Brain_Motor&Sensory_(flipped).png',
					alt: 'Aivojen rakenne'
				},
				{
					type: 'p',
					content:
						'Aivojen sisemmät osat vastaavat monista tahdosta riippumattomista mielen toiminnoista. Ne ovat aivojen vanhempia osia ja hyvin samankaltaisia eläinten aivojen kanssa. Tärkeä alue on esimerkiksi limbinen järjestelmä, joka on tärkeä tunteiden, motivaation ja muistin toiminnassa. Limbisen järjestelmän osia ovat esimerkiksi hippokampus ja mantelitumake. Hippokampus on tärkeä osa muistin kannalta. Sen avulla nyt mielessä olevat asiat siirtyvät pitkäkestoiseen muistiin. Mantelitumake liittyy tunteisiin, esimerkiksi pelkoon ja vihaan.'
				},
				{
					type: 'img',
					content: '/img/Blausen_0614_LimbicSystem.png',
					alt: 'Limbinen järjestelmä'
				},
				{
					type: 'ul',
					content: [
						'Liila: hippokampus, joka on yhteydessä muistin toimintaan.',
						'Keltainen: osa talamuksesta, on yhteydessä viestien välittämiseen eri osiin aivoissa',
						'Pieni sininen pallo liilan päässä: mantelitumake, joka on yhteydessä tunnereaktioiden syntymiseen.',
						'Turkoosi: Hypotalamus, joka on yhteydessä hormonaaliseen toimintaan ja joka säätelee ihmisen kehon toimintoja, kuten lämpötilaa, väsymystä, kylläisyyttä'
					]
				},
				{
					type: 'p',
					content:
						' Aivojen kuorikerros ja sisemmät osat ovat jatkuvasti vuorovaikutuksessa keskenään. Opiskelija saattaa hermoilla kurssitöidensä kanssa lukiossa. Töitä on paljon ja aikaa vähän. Hermostuessa aivojen sisemmät ja vanhemmat osat, esimerkiksi mantelitumake, reagoivat tähän stressaavaan tilanteeseen. Stressihormonit alkavat vaikuttaa elimistössä. Opiskelija ei välttämättä edes ehdi tiedostaa tätä kehon reaktiota. Sydän sykkii ja kehon valtaa epämiellyttävä stressaantunut olo.  Stressaavassa tilanteessa elimistö voi aktivoitua ihmisen tahdosta riippumatta ja se voi tuntua epämiellyttävältä. Aivot käyvät kokoajan sisäistä keskustelua. Ihminen ei tarvitse välttämättä mitään ulkopuolista uhkaa tai varaa hermostumiselle, vaan mielessä pyörivät ajatukset voivat käynnistää stressireaktion. Tunteita voidaan kuitenkin oppia rauhoittelemaan itse. Aivojen sisempien osien reagoidessa voi opiskelija säädellä tunteitaan aivokuoren rauhoittelevalla viestillä, kuten: “Kaikki on hyvin, kyllä minä selviän tästä.” “ Teen yhden asian kaikessa rauhassa kerrallaan ja kyllä se siitä.”  Terveellisillä elämäntavoilla on myös positiivinen vaikutus hermoilun hallintaan. Väsyneenä, nälkäisenä tai alkoholin vaikutuksen alaisena tunteiden säätely voi olla vaikeampaa'
				},
				{
					type: 'img',
					content:
						'/img/Phineas_Gage_GageMillerPhoto2010-02-17_Unretouched_Color_Cropped.jpg',
					alt: 'Phineas Cage'
				},
				{
					type: 'p',
					content:
						'Tietoa aivojen yhteydestä ihmisen psyykkiseen toimintaan on saatu esimerkiksi tapausten avulla. Nämä ovat usein aivovauriopotilaita. Eräs tunnettu tapaus on Phineas Gage. Hän joutui onnettomuuteen Yhdysvalloissa rautatietyömaalla 1848. Työmaalla räjähti ja pitkä rautakanki iskeytyi hänen päänsä läpi. Rautakanki oli kolmen senttimetrin paksuinen. Onnettomuus vaurioitti Gagen otsalohkoa. Phineas Gage selvisi hengissä ja pystyi esimerkiksi puhumaan ja kävelemään aika pian onnettomuuden jälkeen. Onnettomuudella oli kuitenkin suuria vaikutuksia Gagen psyykkiseen toimintaan. Ennen tarkasta, sosiaalisesti taitavasta ja tavallisesta miehestä tuli äkkipikainen, kärsimätön ja impulsiivinen. Otsalohkon alueen vaurio vaikutti Gagen kykyyn säädellä tunteitaan ja toimintaansa. Eli otsalohkon vaurio vaikutti hänen sosiaaliseen käyttäytymiseen ja  tunteiden säätelyyn. '
				},
				{
					type: 'p',
					content:
						'Toinen tunnettu tapaus on Henry Molaison (H.M). Hän sairasti epilepsiaa ja kohtaukset olivat kovia. Kohtausten vähentämiseksi häneltä poistettiin aivoista joitain osia vuonna 1953. Esimerkiksi molemmista aivopuoliskoista poistettiin suurin osa hippokampuksesta ja sen lähialueista. Epilepsiakohtaukset helpottivat leikkauksen jälkeen, mutta valitettavasti leikkaus vahingoitti myös H.M:n muistia. Hän ei enää pystynyt painamaan mieleensä uusia asioita. Leikkauksen jälkeen hän unohti kaiken kokemansa 30 sekunnin kuluttua tapahtuneesta. Suuri osa muistoista ennen leikkausta kuitenkin säilyi, eikä hänen älykkyydessään tapahtunut suuria muutoksia. Hän pystyi esimerkiksi keskustelemaan hoitajien kanssa normaalisti, mutta nämä keskustelut eivät tallentuneet hänen muistiinsa. Hän ei enää myöhemmin muistanut henkilöitä, joiden kanssa oli keskustellut. Lääkärit olivat joka tapaamiskerralla hänelle vieraita ihmisiä. Tieto ei ollut tallentunut pitkäkestoiseen muistiin. Tämän tapauksen avulla on saatu paljon tietoa hippokampuksen merkityksestä muistin toiminnalle. Hippokampus on tärkeä aivojen osa uusien muistojen muodostamisessa. H.M tutkittiin vuosikymmenien ajan ja havaittiin, että vaikka uusia tietoja ja tapahtumia ei enää tallentunut H.M:n muistiin, pystyi hän kuitenkin oppimaan uusia taitoja, esimerkiksi sorminäppäryyttä vaativia taitoja.'
				}
			]
		},
		{
			id: 6,
			header: 'Synnynnäinen temperamentti',
			text: [
				{
					type: 'p',
					content:
						'Temperamentti on persoonallisuuden biologinen perusta. Jo syntymästä lähtien olemme erilaisia. Vastasyntyneet vauvat eroavat esimerkiksi siinä, miten helposti itku tulee ja miten säännöllisesti he nukkuvat ja syövät. Synnynnäinen temperamentti on se pohja, jolle ihmisen persoonallisuus rakentuu. Elämänkokemukset vaikuttavat meihin paljon, mutta jotkin aikuisten väliset erot voivat olla selitettävissä temperamentilla. Toinen meistä ärtyy helposti, toinen taas tuntuu aina rauhalliselta. Toinen meistä kiinnittää helposti huomiota ympärillä oleviin ääniin ja tapahtumiin, toinen pystyy keskittymään kirjan lukemiseen vaikka rakennustyömaalla. Näissä tilanteissa kyse voi olla temperamenttieroista. Synnynnäinen temperamentti säilyy elämän aikana, mutta kehitys, kasvatus ja oppiminen voivat vaikuttaa sen ilmaisemiseen. Helposti ärsyyntyvä oppii elämänsä aikana käsittelemään ärtymystään eri tavoilla kuin lapsena. Aikuisena hän tuskin enää heittäytyy lattialle huutamaan vaan hän voi esimerkiksi rauhoitella itseään musiikkia kuuntelemalla. Temperamenttierot johtuvat eroista henkilöiden hermoston toiminnassa eli kyseessä on biologinen tekijä ihmisen toiminnan taustalla. Näitä eroja selittävät perintötekijät, mutta myös sikiöaikana koettu äidin päihteidenkäyttö tai voimakas stressi voivat vaikuttaa hermoston toimintaan.'
				},
				{
					type: 'p',
					content:
						'On hyvä huomioida, että ei ole olemassa hyvää tai huonoa temperamenttia, vaan olennaista on se, miten sopeutuu ympäristöönsä. Sama temperamenttipiirre voi olla yhdessä ympäristössä vahvuus ja toisessa ympäristössä heikkous. Esimerkiksi lapsi, jolla on voimakas tunneilmaisu ja joka osaa vaatia huomiota, saa hoitoa haastavissa olosuhteissa kuten slummeissa ja selviää hengissä. Sama temperamentti voi taas rauhallista työskentelyä vaativassa luokkahuoneessa johtaa konflikteihin muiden ihmisten kanssa. Hyvä on myös muistaa, että temperamentin ilmaisu muuttuu elämän aikana, opimme säätelemään käyttäytymistämme eri tilanteissa ja sopeutumaan erilaisiin ympäristöihin.'
				},
				{
					type: 'p',
					content:
						'On olemassa erilaisia temperamenttiteorioita, jotka kuvailevat yksilöiden välisiä eroja. Yksi klassikko on tutkijoiden Thomasin ja Chessin teoria temperamenttipiirteistä 1970-luvulta. He jakoivat temperamentin kolmeen tyyppiin: helppo, hitaasti lämpenevä ja haastava temperamentti. Helppo temperamentti tarkoittaa sitä, että lapsella on säännöllinen rytmi syömisessä ja nukkumisessa, hän sopeutuu helposti muutoksiin ja hänellä on positiivinen mieliala. Lapsi osoittaa tunteitaan vaimeasti ja hänellä on halu lähestyä uusia asioita tai ihmisiä. Hitaasti lämpenevä temperamentti tarkoittaa sitä, että uuteen suhtaudutaan negatiivisesti, hieman varauksella ja muutokset ovat vaikeita. Hitaasti lämpenevän temperamentin omaava lapsi tarvitsee aikaa totutella uusiin asioihin kuten vaikka kylpemiseen tai uusiin ihmisiin. Hän ei suin päin syöksy kohti uusia kokemuksia. Mutta ajan kuluessa lapsi osoittaa niihin mielenkiintoa ja positiivista suhtautumista. Hän tarvitsee vain aikaa totutella, hän sopeutuu hitaasti. Haastava temperamentti on temperamenttityyppi, johon liittyy epäsäännöllinen uni- ja ruokailurytmi. Vauva on joskus nälkäinen jo tunnin kuluttua, joskus taas nälkä tulee vasta pitkän ajan kuluttua. Unirytmi on vaikea löytää. Lapsi on usein pahalla päällä ja hän itkee herkästi, tunneilmaisu on voimakasta. Tämän teoria korostaa temperamentin ja ympäristön vuorovaikutusta. Lapsissa on eroja ja lapsen temperamenttityypin ymmärtäminen auttaa vanhempia suhtautumaan lapseen siten, että se sopii yhteen lapsen temperamentin kanssa. Hitaasti lämpenevä temperamentti tarvitsee aikaa totutteluun eikä tällaista lasta tule pakottaa liian nopeasti esimerkiksi uusiin harrastuksiin. Haastava temperamentti tarvitsee rutiineja ja aikuisen rauhoittelua tunteiden myllätessä. Hyvä on huomioida, että kaikki lapset eivät sovi näihin temperamenttityyppeihin vaan he voivat olla jotain niiden väliltä. '
				},
				{
					type: 'p',
					content:
						'Mary Rothbart erottelee temperamentista kolme ulottuvuutta. Nämä ovat itsesäätely, taipumus kokea negatiivisia tunteita sekä ulospäinsuuntautuneisuus. Itsesäätelyllä tarkoitetaan sitä, että miten henkilö pystyy itse ohjaamaan tarkkaavaisuuttaan, käyttäytymistään ja tunteitaan. Toisille oman käyttäytymisen säätely on haastavampaa kuin toisille. Ihmisten välillä on eroa myös sen suhteen, miten herkästi he kokevat negatiivisia tunteita esimerkiksi pelkoa. Ulospäinsuuntautuneisuus selittää sitä, että miten kiinnostunut henkilö on hakeutumaan muiden seuraan. Toiset ovat luonnostaan ujompia muiden seurassa, toiset hakevat mielellään kontaktia toisten ihmisen kanssa. Temperamentin suhteen olemme yksilöllisiä ja tieto omasta temperamentista voi olla hyödyllistä ja auttaa ymmärtämään omaa käyttäytymistä eri tilanteissa.'
				}
			]
		},
		{
			id: 7,
			header: 'Ympäristö muovaa aivoja ',
			text: [
				{
					type: 'p',
					content:
						'Ympäristö muovaa aivoja. Aivot ovat supermuovautuva elin. Plastisiteetti tarkoittaa sitä, että aivot muovautuvat sen mukaan miten niitä käytetään. Plastisiteetti toimii “use it or loose it” - periaatteella. Ne hermosoluyhteydet, joita käytetään, vahvistuvat. Ne hermosoluyhteydet, joita ei käytetä, katoavat. Eli aivojakin voi siis jumpata harjoittelemalla. Tavoitteelllinen ja sinnikäs harjoittelu vaikuttaaa aivoihin. Oppiessa aivot muodostavat koko ajan uusia yhteyksiä. Erityisesti aivokuoren alueella aivojen muovautuvuus on vahvaa.'
				},
				{
					type: 'p',
					content:
						' Ihminen tarvitsee virikkeitä sekä sosiaalista tukea itsensä toteuttamiseen sekä tavoitteidensa saavuttamiseen. Aktiivisuuteen kannustava ympäristö tukee aivojen kehitystä. Erilaisten haasteiden, tehtävien ja päämäärien eteen työskentely tekee aivoista tehokkaammat. Erilaiset oppimiskokemukset muovaavat aivoja ja mahdollistavat ihmisen älykkään toiminnan.'
				}
			]
		},
		{
			id: 8,
			header: 'Rottien hermoston muovautuvuus',
			text:
				'Greenough tutki 1970- luvulla virikkeellisen ympäristön vaikutuksia aivoihin. Hän laittoi ryhmän rottia virikkeelliseen eli leluja sisältävään ympäristöön kasvamaan. Tässä virikkeellisessä ympäristössä oli erilaisia esineitä, leikkikaluja sekä kavereita. Toinen ryhmä rottia laitettiin yksin häkkeihin, joissa ei ollut leluja. Rotat elivät näissä ympäristöissä nuoruuteen asti. Virikkeellinen ympäristö vaikutti aivojen rakenteeseen. Kokemukset kehityksen aikana vaikuttivat siten, että hermosolut muodostivat uusia yhteyksiä muiden hermosolujen kanssa. Virikkeellisessä sosiaalisessa ympäristössä eläneiden rottien hermosolut olivat haaroittuneempia ja tehokkaampia kuin ei -virikkeellisessä ympäristössä eläneiden rottien. Hyvä on huomioida, että virikkeiden hyöty oli suurinta, mikäli rotalla oli muita rottakavereita mukana.'
		},
		{
			id: 9,
			header: 'Susilapset',
			text: [
				{
					type: 'p',
					content:
						'Hyvä esimerkki aivojen muovautuvuudesta ovat harvinaiset villilapset eli susilapset. He ovat ilman muita ihmisiä kehittyneitä lapsia. Eli heidät on jostain syystä hylätty ja he ovat eläneet ilman muiden ihmisen seuraa. Näillä lapsilla aivot ovat muovautuneet vastaamaan ympäristön haasteisiin ja tämä ympäristö on aika erilainen kuin muilla lapsilla. Esimerkiksi luonnossa eläessä aivot ovat muovautuneet käsittelemään hajuaistimuksia tehokkaasti. Hajuaisti on tärkeä, jotta löytää syötävää. Villilapsilla aivot eivät ole muovautuneet käsittelemään kieltä ja puhetta, koska kieltä ei kuule, eikä sitä harjoiteta eristyksissä muista ihmisistä. Villilapsilla onkin vaikeuksia oppia kieltä, koska aivot eivät ole ensimmäisten elinvuosien aikana oppineet käsittelemään kielellisiä ärsykkeitä. Kielen oppimisen kohdalla puhutaan herkkyyskaudesta, eli se on aika, jolloin on sopiva hetki oppia jokin asia. Hermoston kehitys on on otollisessa vaiheessa tämän taidon oppimiselle. Kielen oppimisen kannalta herkkyyskausi on ikävuodet 1-6.'
				}
			]
		},
		{
			id: 10,
			header: 'Amala ja Kamala Intiasta sekä Genie Kaliforniasta',
			text:
				'Intiassa 1920- luvulla löydettiin Amala ja Kamala. He olivat 1,5-, ja 8- vuotiaita tyttöjä löydettäessä luonnosta. He liikkuivat neljällä jalalla, eivät puhuneet vaan ääntelivät kuin sudet. Nuorempi tytöistä kuoli pian, mutta toinen eli muutamia vuosia. Tätä tapausta on epäilty myös huijaukseksi ja villilapsitapauksiin onkin syytä suhtautua kriittisesti. Toinen hieman tuoreempi tapaus on Genie. Hänet löydettiin 1970-luvulla Kaliforniassa ja Genie oli tuolloin 13-vuotias. Hänen mielenterveysongelmista kärsivä isänsä oli eristänyt hänet yhteen huoneeseen. Genie ei kuullut puhetta eikä hänellä juurikaan ollut virikkeitä. Hänen isänsä löi häntä, mikäli hän äänteli, myös hänen liikkumistaan rajoitettiin. Hänet oli esimerkiksi kahlittu pottaan. Genie ehti olla vankilassaan 12 vuotta, jonka jälkeen hänen äitinsä jätti miehensä ja otti Genien mukaan. Äiti vei Genien sosiaalitoimistoon. Genie otettiin huostaan ja vanhemmat joutuivat syytteeseen kaltoinkohtelusta. Hänen isänsä teki itsemurhan.'
		},
		{
			id: 11,
			header: 'Ehdollistuminen',
			text: [
				{
					type: 'p',
					content:
						'Koulussa olet ehkä tottunut siihen, että oppitunnit ovat tylsiä. Kun kotona kaivat psykologian oppikirjaa repustasi, alkaa tylsyys valtaamaan mielesi. On kuitenkin mahdollista, että psykologian oppitunnilla innostut asioista ja haluat oppia lisää. Uudet innostuksen kokemukset tunneilla saavat sinut oppimaan uuden reaktion oppikirjoihin ja niiden lukemisesta tuleekin mukavaa.'
				},
				{
					type: 'p',
					content:
						'Edellä olevassa esimerkissä on kyse klassisesta ehdollistumisesta. Klassinen ehdollistuminen tarkoittaa sitä, että johonkin asiaan syntyy uusi reaktio. Pavlovin koirakoe on tunnettu tutkimus tästä ilmiöstä. Kun koiralle annetaan ruokaa, se kuolaa. Pavlov yhdisti ruoan kellon kilinään ja hiljalleen koira oppi reagoimaan uudella tavalla eli se ehdollistui siihen, että kellon kilinä tarkoittaa ruokaa. Kuola alkoi valua jo pelkästä kellon kilinästä. Eli johonkin asiaan (kellon kilinä) opittiin reagoimaan tietyllä tavalla (kuola). Tämä ilmiö on sinulle ehkä tuttu. Mikäli syöt jotain tiettyä ruokaa juuri ennen oksennustaudin puhkeamista, voi sinulle syntyä vastenmielisyys tätä ruokaa kohtaan. Jos jäätelön syömisen jälkeen sairastut vatsatautiin, voi jäätelö alkaa ällöttämään. Vaikka jäätelöllä ei oikeasti ollut mitään tekemistä oksentamisen kanssa. Tätä kutsutaan aversioksi eli vastenmielisyydeksi ja siinä tapahtuu klassinen ehdollistuminen. Myös mainonnassa klassista ehdollistumista hyödynnetään. Automainokset vilisevät vähäpukeisia, kauniita naisia. Ostajan mieleen pyritään saamaan yhteys ostettavan auton ja näiden kaunottarien välillä. Kun ostat auton, saat sitten naisia myös. Siis autoon opitaan reagoimaan tietyllä tavalla. Eli auto tarkoittaa hyvää menestystä myös treffailussa.'
				}
			]
		},
		{
			id: 12,
			header: 'Pikku-Albert',
			text:
				'Pikku-Albert oli noin vuoden ikäinen lapsi, jonka tutkija John Watson opetti pelkäämään kaikkea valkoista ja karvaista. Tämä tapahtui jo 1920- luvulla. Albert ei pelännyt eläimiä, joita hänen eteensä tuotiin. Watson kuitenkin pamautti pelottavan äänimerkin aina kun Albertin läheisyyteen laitettiin valkoinen hiiri. Hiljalleen Albert ehdollistui pelkäämään valkoista hiirtä. Pelon oppimisen taustalla voi olla tällainen klassisen ehdollistumisen mekanismi. Kun koira puree, opit pelkäämään kaikkia koiria. Hammaslääkärissä poraaminen sattuu, niin opit pelkäämään hammaslääkäriä. Tämä tutkimus on epäeettinen. Ei ole hyvä idea opettaa lapselle pelkotiloja tieteen takia. Pikku-Albert on voinut saada trauman tutkimustilanteesta. Tällaista tutkimusta ei voisi enää nykyään tehdä.'
		},
		{
			id: 13,
			header: 'Välineellinen ehdollistuminen',
			text: [
				{
					type: 'p',
					content:
						'Välineellinen ehdollistuminen on oppimisen muoto, jossa opitaan toiminnan seurauksista. Palkkiot ja rangaistukset ovat tässä olennainen asia. Se, mistä palkitaan, vahvistuu yksilön toiminnassa. Äidin kehut saavat lapsen jatkossakin siivoamaan huoneensa. Hyvä arvosana saa opiskelijan jatkamaan ahkeraa opiskelua.  B F Skinner opetti ruokapalkkioilla kyyhkysiä painamaan tiettyä nappulaa. Aina kun kyyhkynen painoi nappia, se sai herkkupalkkion. Näin kyyhkynen oppi painamaan oikein nappuloita. Skinner tutki nimenomaan eläinten käyttäytymistä ja hyvä onkin pohtia, voiko näitä tutkimustuloksia soveltaa lainkaan ihmisiin.'
				}
			]
		},
		{
			id: 131,
			header: 'Monivalintatehtävä: ehdollistuminen',
			btnText: 'Lähetä',
			parts: [
				{
					label: 'Pavlovin koirakoe kuvaa ilmiötä, jossa',
					order: 1,
					type: 'RadioGroup',
					stacked: true,
					items: [
						{
							text:
								'johonkin asiaan syntyy uusi reaktio (klassinen ehdollistuminen)',
							value: 'true'
						},
						{
							text:
								'opitaan asia toiselta ihmiseltä (mallioppiminen)',
							value: 'false'
						},
						{
							text:
								'opitaan toiminnan seurauksista (välineellinen ehdollistuminen)',
							value: 'false'
						}
					],
					correctAnswer: 'klassinen'
				}
			]
		},
		{
			id: 14,
			header: 'Psykologian tieteellistäminen',
			text: [
				{
					type: 'p',
					content:
						'Psykologisiin teoriasuuntauksiin liittyy aina tietynlainen ihmiskuva, eli miten kyseinen suuntaus selittää ihmisen toimintaa, oppimista ja mielenterveyttä. Behaviorismissa ihmiskuvaa voitaisiin luonnehtia mekanistiseksi, eli kiinnostuksen kohteena on vain ihmisen ulkoinen käyttäytyminen. Behaviorismin isänä pidetään John Watsonia (1878-1958). Watson oli sitä mieltä, että hän pystyisi kouluttamaan kenestä tahansa lapsesta lääkärin, juristin tai vaikka taiteilijan. Behaviorismiin liittyy siis ajatus siitä, että ihminen on muokattavissa palkkioiden ja rangaistusten avulla. Tähän liittyy sellainen heikkous, että rangaistukset ja palkkiot eivät aina toimi halutulla tavalla. Yksilöllä on monia ajatuksia ja tunteita, jotka vaikuttavat hänen toimintaansa.'
				},
				{
					type: 'p',
					content:
						'Vaikka behaviorismi on saanut osakseen paljon kritiikkiä, sen vahvuutena voidaan pitää sen tieteellisiä ihanteita. Behaviorismissa psykologisia ilmiöitä, kuten oppimista, tutkittiin järjestelmällisesti. Tavoitteena oli saada objektiivista, eli tutkijasta riippumatonta tietoa.'
				}
			]
		},
		{
			id: 141,
			header: 'Monivalintatehtävä: ehdollistuminen',
			btnText: 'Lähetä',
			parts: [
				{
					label: 'Behaviorismi on psykologian suuntaus, jonka mukaan',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text:
								'ihminen on muokattavissa palkkioiden ja rangaistusten avulla',
							value: 'true'
						},
						{
							text: 'ihminen on aktiivinen tiedonkäsittelijä',
							value: 'false'
						},
						{
							text:
								'yksilön tunteet ja ajatukset ovat aivan keskeisiä tutkimuskohteita',
							value: 'false'
						}
					]
					// correctAnswer: 'true'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 15,
			header: 'Jäljittelevä ihminen',
			text: [
				{
					type: 'p',
					content:
						'Jo syntymästä lähtien vauva jäljittelee muiden ihmisten tekemistä. Tämä jäljittely on ihmisen aivoihin perustuva kyky. Aivokuorella on peilisoluja, jotka aktivoituvat erityisesti toisten ihmisten liikkeestä, äänistä ja ilmeistä. Näin ei tapahdu vain vauvoilla, vaan se on ihmistä läpi elämän ohjaava oppimisen muoto. Psykologiassa jäljittelyä tai matkimista kutsutaan mallioppimiseksi. Mallioppiminen tarkoittaa nimensä mukaisesti mallista oppimista, eli opitaan asia toiselta ihmiseltä. Esimerkiksi lapsi oppii leikkejä, kun näkee muiden leikkimistä.'
				},
				{
					type: 'p',
					content:
						'Albert Bandura oli alunperin behavioristi. Hän uskoi, että ihmisen käyttäytymistä voi muokata ulkoisten ärsykkeiden avulla. Hän kuitenkin hylkäsi behaviorismin ja kehitti sosiaalisen oppimisen teorian, jossa korostetaan toisten ihmisten tarkkailua ja jäljittelyä.  Sosiaalinen oppiminen tarkoittaa sitä, että opiskelija jäljittelee toisten ihmisten toimintaa ja oppii vuorovaikutuksen kautta.'
				}
			]
		},
		{
			id: 16,
			header: 'Yksi ensin toinen perässä',
			text: [
				{
					type: 'p',
					content:
						'Oppiminen on vahvasti sosiaalista, ihminen oppii toisilta. Mutta jäljitteleekö ihminen aina muita? Bandura teki 1960-luvun alussa yhden tunnetuimmista psykologisista tutkimuksista, jossa tutkittiin mallin vaikutusta lapsen aggressiivisuuteen.'
				}
			]
		},
		{
			id: 17,
			header: 'Bobo-nukke',
			text:
				'Bobo-nukke-kokeessa pieni lapsi näkee tv-ruudulta tilanteen, jossa aikuinen on huoneessa bobo-nuken kanssa. Koeryhmän lapset näkivät aikuisen pahoinpitelevän nukkea. Kontrolliryhmä ei nähnyt aikuisen väkivaltaista käyttäytymistä. Kokeen toisessa vaiheessa lapsi jäi nuken kanssa samaan huoneeseen. Koeryhmän lapset pahoinpitelivät nukkea aivan kuten aikuinen oli tehnyt. Tämän lisäksi he kehittelivät uusia tapoja vahingoittaa nukkea, esimerkiksi ampuivat pyssyllä, vaikkei aikuinen ollutkaan tehnyt näin. Kontrolliryhmä ei kohdistanut väkivaltaa nukkeen.'
		},
		{
			id: 18,
			header: 'Sijaisvahvistaminen',
			text: [
				{
					type: 'p',
					content:
						'Banduran mukaan oppiminen on valikoivaa. Esimerkiksi nukkekokeen yhdessä versiossa pahoinpitelevät aikuiset saivat toiselta aikuiselta kielteistä palautetta. Myöhemmin tämän koeryhmän lapset eivät pahoinpidelleet nukkea. Tätä ilmiötä kutsutaan sijaisvahvistamiseksi. Lapsi jäljittelee sellaista toimintaa, jota palkitaan, mutta jos malli saa rangaistuksen, lapsi ei toista tekoa. Lapsi tutkii ja tarkkailee ympäristöään ja pohtii, mitkä käyttäytymismallit ovat hyväksyttyjä, kiinnostavia tai palkittuja, ja lapsi jäljittelee näitä.  Myös mallilla on merkitystä. Lapset jäljittelevät helpommin sellaista henkilöä, jota he ihailevat tai pitävät korkea-arvoisena. '
				}
			]
		},
		{
			id: 181,
			header: 'Tehtävä: mallioppiminen',
			description: 'Miten sosiaalinen oppiminen eroaa behaviorismista?',
			placeholder: 'Kirjoita tähän...'
		},
		{
			id: 19,
			header: 'Sisäinen malli',
			text: [
				{
					type: 'p',
					content:
						' Ihmisen muistiin on tallentunut monenlaisia ajatuksia siitä, miten asiat ovat. Kun olet nähnyt kukkia, muistiisi on tallentunut käsitys kukasta. Todennäköisesti kun mietit kukkaa, näet mielessäsi värikkään, pienen kasvin. Mieti hetki taikuria. Millaisen kuvan näet mielessäsi? Onko hänellä hattu?  Ihmisen mieleen nousevia käsityksiä kutsutaan sisäisiksi malleiksi eli skeemoiksi. Sisäinen malli voi olla siis esimerkiksi jokin asia, esine tai myös toimintamalli. Sisäiset mallit ovat kuin silmälasit, joiden läpi tarkastelet maailmaa. Ja ne syntyvät meille kokemuksen kautta.'
				},
				{
					type: 'p',
					content:
						'Odotukset ja kokemukset vaikuttavat siihen, miten uusi tilanne tulkitaan. Vanhat sisäiset mallit pohjustavat uutta tilannetta vaikka oppitunnilla. Pohjustusvaikutus tarkoittaa sitä, että jokin asia avaa tietynlaisen sisäisen mallin mielessäsi. Esimerkiksi, jos lueskelet lintukirjaa ennen oppituntia, niin tunnilla huomaat lintuja ikkunasta katsoessasi. Pohjustusvaikutus tapahtuu usein automaattisesti eli ilman että ihmisen tiedostaa sen.'
				},
				{
					type: 'p',
					content:
						'Toimintamallit eri tilanteista ovat myös sisäisiä malleja. Ravintolassa yleensä syödään ensin ja maksetaan sitten lasku. Oppitunnilla otetaan ensin kirjat esiin, sitten tarkastetaan läksyt ja sen jälkeen opiskellaan uutta asiaa. Sisäiset mallit helpottavat toimintaa, koska monet asiat tapahtuvat automaattisesti, kuin itsestään. Toisaalta sisäiset mallit voivat myös johtaa virheisiin, koska ne ovat niin automaattisia. Emme aina ole tietoisia tavastamme käsitellä tietoa vaan havainnot ja tulkinnat syntyvät usein automaattisesti. Tämä johtuu sisäisten mallien vaikutuksesta mielessämme.'
				}
			]
		},
		{
			id: 20,
			header: 'Tarkkaavaisuus suuntaa huomioita',
			text: [
				{
					type: 'p',
					content:
						'Tarkkaavaisuus on huomion kohdistamista. Sisäinen malli ohjaa tarkkaavaisuutta. Mikäli olet kiinnostunut autoista, siihen liittyvät sisäiset mallisi suuntaavat tarkkaavaisuutesi kaupungilla esimerkiksi erikoisiin autoihin. Mikäli olet kiinnostunut muodista, tarkkaavaisuutesi suuntautuu kauppojen näyteikkunoihin. Monta vuotta jalkapalloa pelanneen nuoren henkilön tarkkaavaisuus suuntautuu peliä katsoessa eri asioihin kuin henkilön, joka ei tiedä pelistä mitään. Kokeneella pelaajalla on sisäisiä malleja pelitilanteista ja selkeä käsitys siitä, mitä pelissä pitäisi tehdä ja hänen tarkkaavaisuutensa suuntautuu pelin kannalta olennaisiin asioihin. Kokematon pelaaja ei tunne sääntöjä. Hän ei tiedä miten palloon kannattaa osua ja miten syötellä. Hänellä ei siis ole sisäisiä malleja jalkapallopelistä ja hänen tarkkaavaisuutensa suuntautuu pelin kannalta epäolennaisiin asioihin, kuten vaikka pelaajien ulkonäköön ja asuihin. Sisäiset mallit vaikuttavat siten, että eri ihmisillä voi olla hyvin erilainen havainto samasta asiasta, esimerkiksi jalkapallopelistä.'
				},
				{
					type: 'p',
					content:
						'Oppitunnilla opiskelijan huomio kohdistuu johonkin asiaan, esimerkiksi opettajan opetukseen, kirjan lukemiseen, kaverin juttuihin tai kännykän viesteihin. Sisäinen malli suuntaa tarkkaavaisuutta ja siten tietyt asiat ympäristöstä valikoituvat havainnon kohteeksi. Kiinnostava ja jotenkin opiskelijan aiempaan tietoon linkittyvä oppitunnin aihe valikoituu helpommin tarkkaavaisuuden kohteeksi kuin aivan vieras asia. Tämä johtuu siitä, että opiskelijan sisäiset mallit suuntaavat tarkkaavaisuuden jotenkin jo tuttuun aiheeseen. Opiskelijan kannattaakin valmistautua oppitunnin aiheeseen tekemällä läksyt ja tutustumalla aiheeseen jo kotona. Kannattaa pohtia jo ennen oppituntia, mitä tietää asiasta etukäteen.'
				}
			]
		},
		{
			id: 21,
			header: 'Tee testi ja vastaa kysymykseen',
			//  video: 	'https://www.youtube.com/watch?v=Ahg6qcgoay4',
			description:
				'Tee testi osoitteessa https://www.youtube.com/watch?v=Ahg6qcgoay4 ja kerro, miten se liittyi tarkkaavaisuuteen',
			placeholder: 'Kirjoita tähän...'
		},
		{
			id: 22,
			header: 'Havaintokehä',
			text: [
				{
					type: 'p',
					content:
						'Sisäiset mallit suuntaavat havainnon tekoa ja ihminen saa siten uutta tietoa ympäristöstä. Uudet havainnot ympäristöstä sitten joko vahvistavat tai muokkaavat sisäisiä malleja. Tätä teoreettista mallia kutsutaan havaintokehäksi. Joku voi esimerkiksi ajatella, että naiset ovat huonoja autoilijoita. Tämä on sisäinen malli. Kun hän ajelee liikenteessä, hänen huomionsa kiinnittyy sisäisen mallin ohjaamana vain mokaileviin naiskuskeihin. Nämä uudet havainnot ympäristöstä sitten vahvistavat sisäistä mallia. Voi myös käydä niin, että uusi tieto tuokin mukanaan esimerkin loistavasta naisautoilijoista. Tämän uuden tiedon myötä sisäinen malli voi muokkaantua ja jatkossa henkilö ei enää ajattele naisten olevan huonoja kuskeja. '
				}
			]
		},
		{
			id: 23,
			header: 'Karttatesti',
			text:
				'Taikurit osaavat käyttää hyvin hyödyksi ihmisen tarkkaavaisuutta.  Ihmisen huomio kiinnittyy helposti yhteen tiettyyn asiaan, tällöin puhutaan valikoivasta tarkkaavaisuudesta. Tarkkaavaisuuden ulkopuolelle jäävät asiat sivutetaan, eikä niitä edes välttämättä huomaa. Kun huomio on kiinnittynyt muualle, voi taikuri esimerkiksi piilottaa esineitä tai tuoda takintaskusta esiin uusia. Video nähtävissä osoitteessa: https://www.youtube.com/watch?v=vBPG_OBgTWg'
		},
		{
			id: 231,
			header: 'Monivalintatehtävä: sisäiset mallit',
			btnText: 'Lähetä',
			parts: [
				{
					label:
						'Valitse oikea vaihtoehto. Sisäinen malli suuntaa tarkkaavaisuutta, joten ',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text:
								'ennen oppituntia kannattaa herätellä sisäisiä malleja pohtimalla, mitä tietää oppitunnin aiheesta jo ennestään.',
							value: 'true'
						},
						{
							text:
								'oppitunnilla on mahdotonta valikoida opettajan opetusta tarkkaavaisuuden kohteeksi.',
							value: 'false'
						},
						{
							text:
								'uudet havainnot ympäristöstä vahvistavat aina sisäisiä malleja.',
							value: 'false'
						}
					]
					// correctAnswer: 'true'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 24,
			header: 'Muistin toiminta',
			text: [
				{
					type: 'p',
					content:
						'Kognitiviisessa psykologiassa on 1950-luvulta lähtien tutkittu erityisesti muistia, sen toimintaa ja rakennetta. Tutkimusten avulla on osoitettu vääräksi monia aiempia uskomuksia ihmisen tiedonkäsittelyn rajoista. Aiemmin muisti ymmärrettiin varastona, jonne tietoa tallennetaan. Nykyään korostetaan erityisesti muistin aktiivisuutta. Muistot muuttuvat ja rakentuvat uudelleen. Muisti jaetaan kolmeen osaan:'
				},
				{
					type: 'ul',
					content: [
						'Aistimuisti : Muistin osa, joka säilyttää aistittuja asioita vain muutaman sekunnin verran.',
						'Työmuisti: Muistin osa, jossa tietoa aktiivisesti käsitellään, mutta siellä ne säilyvät muutamista sekunneista puoleen minuuttiin',
						'Pitkäkestoinen muisti : Tänne tiedot tallennetaan ja sieltä ne haetaan takaisin työmuistiin.'
					]
				},
				{
					type: 'p',
					content:
						'Muistia voisi kuvata pullona. Työmuisti on pullon kaula, johon mahtuu vain vähän asioita kerrallaan. Kaulan jälkeen pullo levenee, pitkäkestoiseen muistiin mahtuu paljon enemmän asioita. Jos näitä ei kuitenkaan aktiivisesti palauta mieleen, pitkäkestoisessa muistissa olevat asiat haihtuvat vähitellen pois.'
				}
			]
		},
		{
			id: 25,
			header: 'Työmuisti',
			text: [
				{
					type: 'p',
					content:
						'Työmuisti on se muistin osa, jossa asiat ovat aktiivisena mielessä tällä hetkellä. Kuvittele vaikka miltä näyttää lettipäinen tyttö. Nyt olet ehkä hakenut vanhan mielikuvan pitkäkestoisesta muistista tai tarkkaavaisuutesi on poiminut ympäristöstäsi jonkun tytön, jolla on letit. Mielikuva on nyt työmuistissa aktiivisena eli ajattelet sitä nyt. Voit myös työstää tätä muistoa, esimerkiksi voit purkaa letit tai värjätä ne. Työmuisti kuitenkin kuormittuu helposti, jos ihminen ajattelee montaa asiaa samalla kertaa. Lue esimerkiksi seuraava lista, laita silmät kiinni ja yritä palauttaa mieleesi:'
				},
				{
					type: 'ul',
					content: ['Paita', 'Muki', 'Kahvi', 'Kynä']
				},
				{
					type: 'p',
					content:
						'Muistitko? Tämä ei ollut välttämättä kovin vaikeaa, koska asioita oli vain neljä. Sen sijaan jos määrää kasvattaa, voi listan muistaminen ollakin vaikeaa. Lue seuraava lista läpi, laita silmät kiinni ja yritä muistaa listan asiat:'
				},
				{
					type: 'ul',
					content: [
						'Asunto',
						'Aurinko',
						'Karhu',
						'Leipä',
						'Kukka',
						'Auto',
						'Täti',
						'Kakku',
						'Viivotin',
						'Pullo',
						'Hattu'
					]
				},
				{
					type: 'p',
					content:
						'Jo 1950-luvulla George A. Miller osoitti legendaarisessa tutkimuksessaan “"The Magical Number Seven, Plus or Minus Two..”, että hän pystyi havaitsemaan vain noin seitsemän asiaa eli hahmotusyksikköä kerralla. Nykytutkimuksen mukaan kapasiteetti eli työmuistiin mahtuvien asioiden määrä on 3-7 hahmotusyksikköä.'
				}
			]
		},
		{
			id: 26,
			header: 'Shakkikoe',
			text:
				'Shakkikoe: Simon ja Chase tekivät vuonna 1973 mielenkiintoisen tutkimuksen aloittelevilla ja kokeneilla shakinpelaajilla. Tutkimuksessa pelaajien piti katsoa pelitilanteita ja palauttaa mieleen shakkinappuloiden paikat. Kun nappuloiden määrää kasvatettiin, kokeneet shakinpelaajat pystyivät muistamaan hyvin nappuloiden sijainnit, kun taas aloittelijoiden muistivirheiden määrä nousi. Tätä on selitetty sillä, että kokeneet pelaajat pystyivät rakentamaan yksittäisistä nappuloista ja niiden sijainnista suurempia kokonaisuuksia, jolloin muistaminen vei vähemmän työmuistin kapasiteetista. Aloittelijoilta kokonaisuuksien rakentaminen ei taas onnistunut, jolloin työmuisti kuormittui ja muistiinpalauttaminen vaikeutui. Yllättävää tutkimuksessa oli kuitenkin se, että jos nappuloiden paikat eivät vastanneet oikeita pelitilanteita, kokeneet pelaajat eivät muistaneet paremmin kuin aloittelijat. Tämä tutkimus antaa tukea ajatukselle, että työmuistin kapasiteettia voi laajentaa, jos pitkäkestoisen muistin avulla voi rakentaa pienistä asioista suurempia kokonaisuuksia.'
		},
		{
			id: 27,
			header: 'Pitkäkestoinen muisti',
			text: [
				{
					type: 'p',
					content:
						'Työmuistiin mahtuu vain rajallinen määrä asioita kerrallaan. Sen sijaan pitkäkestoisella muistilla ei ole tällaisia rajoituksia. Oikeastaan asia on toisin päin. Mitä enemmän asioita tallentaa pitkäkestoiseen muistiin, näistä syntyy merkitysten verkostoja, joiden avulla on mahdollista muistaa enemmän.'
				},
				{
					type: 'p',
					content:
						'Sisäiset mallit vaikuttavat muistin toimintaan. Kun lukiolainen opiskelee esimerkiksi ruotsinkielen sanoja,  yksittäisestä sanasta muodostuu sisäisen malli hänen pitkäkestoiseen muistiinsa, osaksi laajempaa merkitysten verkostoa, jossa on muita sanoja, mielikuvia, värejä ja tapahtumia.'
				},
				{
					type: 'p',
					content:
						'Osa tallennetuista asioista, kuten henkilöt ja paikat, ovat muistissa sellaisessa muodossa, että ihminen pystyy niitä sanallisesti kuvaamaan. Esimerkiksi opiskelija voi sanallisesti kuvata omaa perhettään tai kaupunkeja, joissa hän on matkustanut. Tätä osaa pitkäkestoisesta muistista kutsutaan tietomuistiksi. Osa muistoista on kuitenkin sellaisia, joita on vaikea sanallisesti kuvata. Esimerkiksi voi olla vaikea selittää mitä kaikkea tapahtuu pyöräillessä tai uidessa.'
				},
				{
					type: 'p',
					content:
						'Mitä paremmin tieto on muistiin jäsennelty, sitä helpompi se on myös mieleen palauttaa. Myös oppiminen voidaan käsittää sisäisten mallien rakenteluna. Opiskellessasi uutta tietoa sisäiset mallisi rikastuvat tai muokkaantuvat. Olet opiskellut yläkoulun historian tunnilla keskiaikaa. Lukion historian kursseilla saat uutta tietoa, joka laajentaa sisäistä malliasi keskiajasta. Uuden tiedon liittäminen omaan sisäiseen malliin helpottaa oppimista. Siksi oppitunnin aluksi voisi olla hyvä idea pohtia, mitä opiskeltavasta asiasta tietää jo etukäteen, vai tietääkö mitään.'
				}
			]
		},
		{
			id: 271,
			header: 'Monivalintatehtävä: muistin toiminta',
			btnText: 'Lähetä',
			parts: [
				{
					label: 'Mikä seuraavista väittämistä on väärin:',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text:
								'työmuistissa asioita käsitellään aktiivisesti, mutta sinne mahtuu vain vähän asioita kerrallaan',
							value: 'true'
						},
						{
							text: 'pitkäkestoinen muisti kuormittuu helposti',
							value: 'false'
						},
						{
							text:
								'yksilön tunteet ja ajatukset ovat aivan keskeisiä tutkimuskohteita',
							value: 'true'
						}
					]
					// correctAnswer: 'false'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 28,
			header: 'Prosessoinnin tasot',
			text: [
				{
					type: 'p',
					content:
						'Prosessointi tarkoittaa asian käsittelyä. Esimerkiksi Minni opiskelee sanoja englannin kielen sanakokeeseen, eli hän prosessoi tietoa muistissaan. Hän yrittää keskittyä ja toistelee sanoja, jotta ne jäisivät paremmin mieleen, toisin sanoen prosessointi siirtää tietoa pitkäkestoiseen muistiin. Kokeessa näitä tietoja haetaan taas pitkäkestoisesta muistista työmuistiin.'
				},
				{
					type: 'p',
					content:
						'Tietoa voi prosessoida monella eri tavoilla. Minni opettelee sanoja toistamalla. Hän lukee kirjasta sanan “government” ja katsoo sen määritelmän “hallitus”. Minni toistaa sitä mielessään monta kertaa, ja yrittää painaa sen mieleen. Tällaista tiedon käsittelyä kutsutaan <strong> pinnalliseksi prosessoinniksi . Tietoa käsitellään siinä pinnallisella, toistavalla tavalla.'
				},
				{
					type: 'p',
					content:
						'Syvällinen prosessointi on asian mietiskelemistä, pohtimista ja ymmärtämistä.  Lukiossa Minni on tutustunut opiskelutekniikoihin. Englannin tunnilla Minnille kerrottiin, että pelkän toistamisen sijaan opiskelijan kannattaa  tutkia sanaa. Nyt kotona Minni miettii, mitä sanasta tulee mieleen. Hän tutkii sanan kirjoitusasua ja yhteyksiä toisiin sanoihin.'
				}
			]
		},
		{
			id: 29,
			header: 'Tehtävä',
			description:
				'Pohdi, millainen on ollut sinun prosessointitapasi peruskoulussa. Miten luit esimerkiksi sanakokeisiin?',
			placeholder: 'Kirjoita vastaus tähän'
		},
		{
			id: 30,
			header: 'Tehtävä',
			description:
				'Tehtävä: Kuinka monta konsonanttia on sanassa Government? Onko se mielluttävä vai epämiellyttävä sana? Millaisia mielikuvia sinulle tulee sanasta?',
			placeholder: 'Kirjoita vastaus tähän'
		},
		{
			id: 31,
			header: 'Tutkimus sanojen prosessoinnin tasosta',
			text:
				'Vuonna 1973 tutkijat Thomas Hyde ja Jim Jenkins halusivat selvittää, miten sanojen prosessointi vaikuttaa niiden muistamiseen. Hyden ja Jenkinsin kokeellisessa tutkimuksessa koehenkilöt jaettiin kahteen ryhmään ja kummallekin ryhmälle esitettiin pitkä lista sanoja. Ensimmäisen ryhmän piti prosessoida sanaa pinnallisella tavalla. Heidän tehtävänä oli laskea, kuinka monta kertaa kirjain “e” esiintyi sanoissa. Toisen ryhmän tehtävänä oli pohtia, miten miellyttäviä sanat olivat. Tämän jälkeen molempien ryhmien piti palauttaa mieleen edelliset sanat. Kokeen tulos oli, että ensimmäinen ryhmä sai 24% sanoista oikein, kun taas jälkimmäinen ryhmä sai jopa 48%. Tutkimuksen perusteella voi huomata, miten asian miellyttävyyden pohdinta auttaa muistamaan sanoja paremmin kuin jokin mekaaninen tehtävä, jossa lasketaan kirjaimia. Tiedon prosessointi on tärkeää erityisesti silloin, kun opiskellaan suurempia alueita, esimerkiksi reaaliaineissa.'
		},
		{
			id: 32,
			header: 'Opiskelustrategiat',
			text: [
				{
					type: 'p',
					content:
						'Minnillä oli ensimmäisessä jaksossa historian kurssi, jossa oli paljon muistettavaa, kuten aikakausia ja eri tapahtumia. Kurssikokeessa hänen päänsä meinasi räjähtää kaikesta tiedosta. Tietoa oli vaikeaa muotoilla koevastaukseen. Tätä ilmiötä kutsutaan täyden pään ongelmaksi.'
				},
				{
					type: 'p',
					content:
						'Tällaisessa tilanteessa voi helpottaa tiedon jäsentely ja asioiden välisten suhteiden pohtiminen. Miten asiat liittyvät toisiinsa? Eli silloin opiskelija prosessoi eli käsittelee tietoa syvällisesti. Sen sijaan, että opiskelisi vain tietoja sellaisenaan, voi oppimista helpottaa asioiden jäsentely mielessä jo opiskeluvaiheessa. Silloin asiat jäsentyvät mielekkäiksi kokonaisuuksiksi pitkäkestoiseen muistiin ja niiden mieleen palauttaminen voi helpottua.'
				}
			]
		},
		{
			id: 33,
			header: 'Tutkimus erilaisista opiskelustrategioista',
			text:
				'Kirsti Lonka & et al. tekivät lääketieteen opiskelijoilla tutkimuksen eri opiskelutapojen vaikutuksista oppimiseen. Opiskelijat jaettiin kolmeen eri ryhmään. Ensimmäinen ryhmä opiskeli vain kirjan avulla, mutta he eivät tehneet muistiinpanoja. Toinen ryhmä alleviivasi tekstistä olennaisia sanoja. Kolmas ryhmä teki itse muistiinpanoja, esimerkiksi käsitekarttoja. Koetilanteessa viimeinen ryhmä sai parhaat tulokset, ja tasoero näkyi erityisesti soveltavissa tehtävissä. Käsitekarttojen teko on tietoa rakentelevaa tiedonkäsittelyä. Silloin opiskelija käsittelee tietoa monipuolisemmin kuin vaikka vain ranskalaisilla viivoilla muistiinpanoja tekemällä. Eli käsitekarttoja tekemällä opiskelija syväprosessoi tietoa. Silloin tiedonkäsittely ei ole vain tietoa toistavaa ja siksi monet opettajat kehottavat käsitekarttojen tekoon.'
		},
		{
			id: 35,
			header: 'Ohjeita syvälliseen prosessointiin:',
			text: [
				{
					type: 'ul',
					content: [
						'Ennen lukemista vilkaise otsikot. Tämä avaa sisäisiä malleja. Uusi tieto on näin helpompaa yhdistää aiemmin opittuun.',
						'Kirjoita psykologiset termit käsin paperille tai tee muistiinpanot koneelle. Laita kirja kiinni, kun kirjoitat. Näin syvennät tiedon prosessointia.',
						'Yhdistele termeistä laajempi käsitekartta. Yritä käyttää mahdollisimman vähän sanoja. Kirjoita omin sanoin. Käytä värejä. Kirjoita perusteita, miten eri käsitteet liittyvät toisiinsa.'
					]
				}
			]
		},
		{
			id: 36,
			header: 'Metakognitiivinen toiminta',
			text: [
				{
					type: 'p',
					content:
						'Tehokkaaseen oppimiseen liittyvä metakognitiiviset taidot. Metakognitio on vaikea käsite, mutta siitä ei kannata säikähtää. Ilmiö on arkinen ja yksinkertainen opiskelijalle. Metakognitio tarkoittaa tietoisuutta omasta tiedonkäsittelystä. Kun pohdit, miten kannattaisi opiskella, kehität metakognitiivisia taitojasi. Metakognitiiviset taidot kehittyvät iän ja koulutuksen lisääntyessä. Kun opiskelija miettii opiskelustrategioitaan, tarvitsee hän metakognitiivisia taitoja.'
				},
				{
					type: 'p',
					content:
						'Metakognitiivisesti taitava opiskelija ymmärtää mitä hän jo osaa ja mitä ei osaa. Metakognitiivisesti taitava opiskelija pystyy asettamaan itselleen tavoitteita sekä miettimään juuri hänen tarpeisiin sopivia opiskelutapoja. Esimerkiksi oppimisen testaaminen auttaa hahmottamaan omaa osaamistaan, käy siis tekemässä kappaleen lopussa oleva monivalintatesti kognitiivisesta psykologiasta.'
				}
			]
		},
		{
			id: 361,
			header: 'Monivalintatehtävä: prosessointi',
			btnText: 'Lähetä',
			parts: [
				{
					label:
						'Mikä seuraavista väittämistä on oikein: Tutkijat Hyde ja Jenkins huomasivat tutkimuksessaan, että ',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text:
								'sanojen miellyttävyyden pohtiminen on tiedon pinnallista prosessointia',
							value: 'false'
						},
						{
							text:
								'tiedon syvällinen prosessointi tehostaa muistamista',
							value: 'true'
						},
						{
							text:
								'tiedon prosessoinnin tasolla ei ole merkitystä oppimiselle',
							value: 'false'
						}
					]
					// correctAnswer: 'true'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 37,
			header: 'Tiedostamaton mieli',
			text: [
				{
					type: 'p',
					content:
						'Sigmund Freud oli luonnontietelijä, joka uransa alkuvaiheessa leikkeli käärmeitä. Tämä ura ei auennut, mutta sen sijaan hän kehitti menetelmän, psykoanalyysin, jonka avulla saisi avattua ihmisen mielen. Psykoanalyysi on pitkäkestoinen hoitomenetelmä, jossa tavoitteena on avata tiedostamattomia asioita, joita potilas ei itse aktiivisesti pysty ajattelemaan. Potilas makaa sohvalla ja assosioi vapaasti, eli puhuu mitä mieleen tulee. Psykoanalyytikko kuuntelee potilaan kokemuksia, tulkintoja, unia ja ajatuksia. Menetelmässä huomio on erityisesti menneisyydessä tapahtuneissa asioissa. Tavoitteena on tuoda tiedostamaton tietoiseksi ja vapautua näistä ahdistavista ja kielletyistä tunteista.'
				},
				{
					type: 'p',
					content:
						'Omana aikanaan Freudin ajatuksia pidettiin hyvin radikaaleina. Hän tutki omia potilaitaan ja muotoili kuuluisan teoriansa näiden pohjalta.  Freud korosti erityisesti mielen tiedostamatonta puolta, eli ajatuksia, tunteita. Ihmisen mieli koostuu Freudin mukaan kolmesta osasta. EGO, minä, on ihmisen mielen tietoinen osa, eli se, mitä ihmisellä on mielessään nyt. ID, se,  on mielen tiedostamaton osa, eläimellinen viettipohja, joka tavoittelee mielihyvää. Mielellä on myös kolmas osa, SUPER-EGO, yliminä, joka on enimmäkseen tiedostamaton, mutta ihminen pystyy myös tiedostamaan sen toimintaa.'
				},
				{
					type: 'p',
					content:
						'Tässä video Freudista: https://www.youtube.com/watch?v=mQaqXK7z9LM'
				},
				{
					type: 'p',
					content:
						'Freudin mukaan mielihyvä oli pääosin seksuaalista. Freud huomasi, että hänen potilaansa kärsivät usein ahdistuksesta ja näkivät häiritseviä painajaisia. Unissa potilaiden tiedostamattomat vietit pääsivät tajuntaan. Freudin seksuaalisuutta korostanut psykologia oli hänen elinaikanaan poikkeuksellista. Sata vuotta sitten Euroopassa ilmapiiri ei ollut niin vapaamielinen kuin nykyään, joten Freudin ajatuksia arvosteltiin erityisesti moraalittomina.'
				},
				{
					type: 'p',
					content:
						'Ego yrittää pitää yllä mielen tasapainoa. ID lähettää EGO:lle viestejä, mutta näitä ei voi aina toteuttaa. Halujen toteuttaminen ei ole aina mahdollista tai ympäristöön sopivaa. Freud huomasi, että EGO torjuu näitä eläimellisiä viettejä. Ego käyttää puolustusmekanisteja eli defenssejä. Freudin määritteli muutamia defenssejä, kuten torjunta, kieltäminen, sublimaatio ja projektio '
				},
				{
					type: 'ul',
					content: [
						'Torjunnassa ego yrittää vältellä aiheen käsittelemistä, eli torjuu sen pois tietoisuudesta. Esimerkiksi opiskelija ei halua ajatella huonoa koenumeroa.',
						'Kieltämisessä tapahtuma tai asia on niin ahdistava, että mieli ei pysty käsittelemään sitä, niinpä ihminen sulkee sen pois mielestä. Esimerkiksi opiskelija ei edes muista, että hän on saanut kokeesta hylätyn ja hänen pitäisi mennä uusiintaan, muttei tiedosta sitä.',
						'Sublimaatiossa ego purkaa ahdistusta johonkin toiseen tekemiseen. Esimerkiksi koeviikolla opiskelija voi käydä lenkkeilemässä tai siivota koko asunnon puhtaaksi.',
						'Projektiossa ego siirtää ahdistuksen johonkin toiseen. Esimerkiksi alkaa syyttämään vanhempia tai opettajaa huonosta koearvosanasta.'
					]
				},
				{
					type: 'p',
					content:
						'Superego eli yliminä ohjaa ihmisen moraalia ja asettaa erilaisia normeja toiminalle. Se kehittyy noin 3-6 vuotialle. Silloin lapsi käy niin kutsutun oidipaalisen vaiheen, jossa poikalapset rakastuvat äitiin ja tyttölapset isään. Taustalla on antiikin Kreikan satu Oidipuksesta, jonka vanhemmat hylkäsivät, mutta myöhemmin hän tietämättään rakastui äitiinsä ja murhasi isänsä. Pojat on tässä vaiheessa mustasukkaisia isälleen, koska poika joutuu jakamaan äidin isän kanssa. Isä on kuitenkin liian ylivertainen pojalle. Konflikti ratkeaa sillä, kun poika alkaa ihailemaan isäänsä ja haluaa tulla samanlaiseksi. Tässä vaiheessa lapselle kehittyy SUPER-EGO, joka on vastaa vähän samaa kuin omatunto. Super-ego rajoittaa egoa ja idiä. Se on kuin on laivan kapteeni, joka pitää laivan kurssin oikeassa suunnassa.  Super-ego voi olla kuitenkin liian korostunut, jolloin ihmiselle myöhemmässä elämässä voi Freudin mukaan kehittyä erilaisia neurooseja, eli pakkotoimintoja. Esimerkiksi pakonomaista tarvetta pestä käsiä. Alikehittynyt superego voi taas vaikuttaa siihen, että ihminen suostu hyväksymään auktoriteettejä.'
				}
			]
		},
		{
			id: 371,
			header: 'Monivalintatehtävä: psykoanalyysi',
			btnText: 'Lähetä',
			parts: [
				{
					label:
						'Mikä seuraavista väittämistä on oikein: Psykoanalyysi on psykologian suuntaus ja hoitomenetelmä, joka korostaa',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text:
								'sisäisten mallien ja tiedon käsittelyn merkitystä',
							value: 'false'
						},
						{
							text: 'tiedostamattoman merkitystä',
							value: 'true'
						},
						{
							text: 'palkkioiden ja rangaistusten merkitystä',
							value: 'false'
						}
					]
					// correctAnswer: 'true'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 372,
			header: 'Monivalintatehtävä: defenssit',
			btnText: 'Lähetä',
			parts: [
				{
					label:
						'Opiskelija on saanut matematiikan kokeesta hylätyn arvosanan. Äiti tiedustelee kotona, että miten kurssi etenee ja että miten koe meni. Mutta opiskelija yrittää koko ajan vaihtaa puheenaihetta, hän ei halua ajatella koko asiaa. Kyseessä on defenssi, mutta mikä seuraavista?',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text: 'projektio',
							value: 'false'
						},
						{
							text: 'sublimaatio',
							value: 'false'
						},
						{
							text: 'torjunta',
							value: 'true'
						}
					]
					// correctAnswer: 'true'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 38,
			header: 'Humanistinen psykologia',
			text: [
				{
					type: 'p',
					content:
						'Psykologiatieteessä 1900-luvun alkupuoli oli psykoanalyysin ja behaviorismin valtakautta. Psykoanalyysissa porauduttiin lapsuuden traumaattisiin kokemuksiin. Behaviorismissa uskottiin palkkioiden ja rangaistusten voimaan kasvatuksessa. 1970-luvulla psykologiaan syntyi uusia virtauksia. Osa psykologeista koki psykoanalyysin liian sairauskeskeiseksi. Behaviorismi koettiin liian konemaiseksi. Psykologit, esimerkiksi Carl Rogers ja Abraham Maslow, halusivat tuoda vahvistaa myönteisempää ihmiskäsitystä. Syntyi humanistinen psykologia, jossa korostettiin ihmisen voimavaroja, vapautta ja potentiaalia.'
				},
				{
					type: 'p',
					content:
						'Carl Rogers ei niinkään ollut yliopistotutkija, vaan hän oli luonut uraa psykologin työssä. Hän halusi luoda uudenlaisia terapiamuotoja, jossa asiakas otettaisiin paremmin huomioon. Rogers uskoi, että jokaisella ihmisellä on sisäinen tarve toteuttaa itseään. Kasvatuksessa toruminen, rankaiseminen, nöyryyttäminen ja kurittaminen voi vaikuttaa lapseen siten, että hän ei uskalla kuunnella sisäistä ääntään, vaan alkaa elää muiden halujen, toiveiden ja käskyjen mukaisesti. Rogersin mukaan terapiassa on tärkeää asiakkaan kohtaaminen, kuunteleminen ja ymmärtäminen.'
				},
				{
					type: 'p',
					content:
						'1970-luvulla humanististen psykologien ajatukset olivat suosittuja, mutta humanistinen psykologia sai myös kritiikkiä siitä, ettei näitä ajatuksia voitu tieteellisesti todistaa. Viimeisten vuosikymmenien aikana positiivinen psykologia on vahvistunut, kun näitä ajatuksia on vihdoin onnistuttu perustelemaan tieteellisen tutkimuksen avulla.'
				}
			]
		},
		{
			id: 39,
			header: 'Sisäinen ja ulkoinen motivaatio',
			text: [
				{
					type: 'p',
					content:
						'Motiivi tarkoittaa syytä toiminnalle. Motivaatio on taas laajempi käsite, joka tarkoittaa eri motiivien kokoelma, joka saa ihmisen toimimaan, esimerkiksi opiskelemaan, tekemään töitä, seurustelemaan tai harrastamaan.  Sisäinen motivaatio tarkoittaa halua tai kiinnostusta tehdä jotain asiaa pelkästään sen asian itsensä vuoksi. Esimerkiksi lasten leikkiminen perustuu sisäiseen motivaatioon, eikä siitä saatavaan palkkioon, vaan leikki itsessään on palkitsevaa. Harrastusten motivaatio on usein sisäistä.  Ulkoinen motivaatio tarkoittaa sitä, että asiaa tehdään jonkun muun syyn takia. Esimerkiksi kesätyötä siitä saatavan palkan vuoksi.'
				},
				{
					type: 'p',
					content:
						'Yhdysvaltalaiset tutkijat Edward L. Deci ja Richard M. Ryan ovat luoneet itseohjautuvuusteorian, joka on kenties tunnetuin motivaatioteoria tällä hetkellä. Deci ja Ryan kuvaavat motivaatiota janana. Toisessa ääripäässä on tunne, jossa ihminen ei halua ollenkaan tehdä jotain asiaa. Nämä ovat yksilöllisiä. Mieti, mitkä voisivat olla sinulle tällaisia asioita. Toisena ääripäänä on sisäinen motivaatio, jolloin tekeminen on itsessään todella kiinnostavaa. Motivaation laatu voi kuitenkin muuttua, esimerkiksi ulkoisesta sisäiseksi. Deci ja Ryan selvittivät tutkimuksissaan, että sisäisen motivaatiota vahvistaa kolme eri tekijää:'
				},
				{
					type: 'ul',
					content: [
						'Autonomia eli vapaus:  Jos esimerkiksi työntekijälle annetaan vapautta päättää asioista, sisäinen motivaatio vahvistuu. Sen sijaan pakottaminen laskee motivaatiota.',
						'Kompetenssi eli kyvykkyyden tunne:  Esimerkiksi, jos opiskelijalle tulee tunne, ettei hän osaa mitään, motivaatio laskee. Sen sijaan, jos opiskelussa on vahva tunne siitä, että osaa, motivaatio kasvaa.',
						'Sosiaalinen tuki:  Esimerkiksi, jos opiskelija kokee, ettei hän saa apua ongelmaansa, niin motivaatio laskee. Sen sijaan jos ongelmien ilmestyessä opiskelija saa tarvitsemaansa apua, niin tämä nostaa motivaatiota.'
					]
				},
				{
					type: 'p',
					content:
						'Suomalainen filosofi, Frank Martela, on tehnyt viimeisten vuosien ajan yhteistyötä Decin ja Ryanin kanssa. Hän kehitti itseohjautuvuusteoriaan neljännen tekijän. Motivaatiota nostaa se, jos henkilö kokee tekemisen merkitykselliseksi. Esimerkiksi vapaaehtoistoiminnassa ihminen voi kokea oman työnsä tärkeäksi. Opiskelun kannalta olennaista on huomata, että motivaatioon on todellakin mahdollista vaikuttaa. Jos nyt mikään ei tunnu kiinnostavan, voi yrittää herätellä sisäistä motivaatiota.'
				}
			]
		},
		{
			id: 391,
			header: 'Monivalintatehtävä: motivaatio',
			btnText: 'Lähetä',
			parts: [
				{
					label: 'Sisäinen motivaatio tarkoittaa sitä, että',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text: 'tehtävä itsessään kiinnostaa ja innostaa',
							value: 'true'
						},
						{
							text: 'asiaa tehdään siitä saatavan palkkion takia',
							value: 'false'
						},
						{
							text: 'henkilöllä ei ole motivaatiota tehdä mitään',
							value: 'false'
						}
					]
					// correctAnswer: 'true'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 40,
			header: 'Virtaus-kokemus',
			text: [
				{
					type: 'p',
					content:
						'Kun opiskelija löytää sisäisen motivaation opintoihinsa, voi hän kokea huippukokemuksia eli virtausta. Virtaus (flow) tarkoittaa huippukokemusta, jolloin tekeminen vie mukanaan, ajantaju häviää ja keskittyminen on vahvaa. Tutkija, jolla on mahdottoman vaikea nimi, Mihaly Csikszentmihalyi, halusi selvittää, millaisissa tilanteissa ihminen saavuttaa flown.'
				},
				{
					type: 'p',
					content:
						'Hän tutki koehenkilöitä ns. otantamenetelmän avulla. Otantamenetelmässä tutkittava kantaa hälytintä, joka piippaa sattumanvaraisesti muutaman kerran päivässä. Piippauksen jälkeen tutkittavat vastaavat seuraavanlaisiin kysymyksiin:'
				},
				{
					type: 'ul',
					content: [
						'Missä olet?',
						'Mitä olet tekemässä?',
						'Miten haastavaa se on?',
						'Millainen tunnetila sinulla on nyt?'
					]
				},
				{
					type: 'p',
					content:
						'Usein ajatelllaan, että virtauskokemus olisi jotain rentouttavaa, mutta Csikszentmihalyi huomasi päinvastaista.  Otantamentelmän tuloksena nähtiin, että virtauskokemukseen vaikuttaa tehtävän haasteellisuus ja koehenkilön usko omiin kykyihin, eli kyvykkyys.'
				},
				{
					type: 'ul',
					content: [
						'Jos haaste oli liian korkea ja tutkittavan oma kyvykkyys matalaa, koehenkilöt ahdistuivat.',
						'Jos haaste oli liian matala ja tutkittavan oma kyvykkyys korkealla, koehenkilöt tylsistyivät.',
						'Jos haaste oli liian matala ja tutkivan oma kyvykkyys matala, koehenkilöt olivat apaattisessa tilassa, eli täysin luovuttaneita ja alakuloisia.'
					]
				},
				{
					type: 'p',
					content:
						'Virtauskokemuksen saavuttamiseen vaadittiin riittävän korkea haaste, toistaalta kokemus siitä, että kykenee vastaamaan haasteeseen.'
				}
			]
		},
		{
			id: 41,
			header: 'Tulkintoja itsestä ja muista',
			text: [
				{
					type: 'p',
					content:
						'Lukiolainen voi joskus myöhästyä tunnilta tai unohtaa läksyt. Hän voi saada hyviä tuloksia kokeesta tai epäonnistua. Näiden tapahtumien jälkeen ihminen selittää omaa ja toisen toimintaa. Miksi minulle kävi näin? Kenen vika se oli?'
				},
				{
					type: 'p',
					content:
						'Attribuutiot ovat syiden selityksiä. Ihminen voi selittää onnistumisia ja virheitä eri tavoin. Näitä kutsutaan attribuutiotyyleiksi. Jos opiskelija on epäonnistunut kokeessa, hän voi ajatella sen johtuneen esimerkiksi siitä, että hän ei lukenut tarpeeksi. Syyn selitys eli attribuutio on tässä tapauksessa sisäinen, syy on tekijässä itsessään.'
				},
				{
					type: 'p',
					content:
						'"Valmistauduin huonosti, syy on minun. En vaan opi mitään”. '
				},
				{
					type: 'p',
					content:
						'Näin moni opiskelija voi ajatella, että huonon koemenestyksen syy on hänessä.  Toisaalta opiskelija voi ajatella näin: '
				},
				{
					type: 'p',
					content:
						'“Se opettaja opetti huonosti. Kirja oli sekava. Siksi minä sain huonon numeron.”'
				},
				{
					type: 'p',
					content:
						'Syyn selitys eli attribuutio on tässä tapauksessa ulkoinen, syy on muissa. Opiskelija voi myös attribuoida huonon koemenestyksen muuttuvaksi eli väliaikaiseksi: '
				},
				{
					type: 'p',
					content:
						' “Viime matikan koe meni tavallista huonommin, ensi kerralla menee paremmin. Seuraavaan kokeeseen voin valmistautua huolellisemmin.” '
				},
				{
					type: 'p',
					content:
						'Tämän vastakohtana on pysyvä attribuointi. Opiskelija saattaa uskoa, että kyseinen aine menee aina huonosti:'
				},
				{
					type: 'p',
					content:
						'“En ikinä opi matematiikkaa. Olen aina ollut huono siinä, niinpä en lukiossakaan osaa sitä.”'
				},
				{
					type: 'p',
					content:
						'Atrribuutiosta voidaan erotella vielä kaksi muuta vastakkaista tyyliä. Syy voidaan nähdä joko kontrolloitavaksi tai kontrolloimattomaksi. Kontrolloitavuus tarkoittaa sitä, että syy nähdään tilannekohtaisena. Opiskelija kokee hallinnan tunnetta ja ajattelee, että voi vaikuttaa syyhyn : “Viime jaksossa en lukenut yhtään kokeisiin, joten sain huonoja numeroita. Ensi jaksossa aion panostaa kunnolla.”'
				},
				{
					type: 'p',
					content:
						'Atrribuutiosta voidaan erotella vielä kaksi muuta vastakkaista tyyliä. Syy voidaan nähdä joko kontrolloitavaksi tai kontrolloimattomaksi. Kontrolloitavuus tarkoittaa sitä, että syy nähdään tilannekohtaisena. Opiskelija kokee hallinnan tunnetta ja ajattelee, että voi vaikuttaa syyhyn : “Viime jaksossa en lukenut yhtään kokeisiin, joten sain huonoja numeroita. Ensi jaksossa aion panostaa kunnolla.”'
				},
				{
					type: 'p',
					content:
						'Kontrolloimaton attribuutio saa opiskelija ajattelemaan, ettei voi vaikuttaa syyhyn: “Ihan sama luenko vai en, saan aina kokeista huonoja numeroita.”  Kontrolloimaton attribuutio on ongelmallista erityisesti epäonnistumisissa. Mikäli opiskelija kokee, ettei voi vaikuttaa esimerkiksi matematiikan opiskelluun, voi hän lannistua ja lopettaa yrittämisen kokonaan. Ajatus voi heikentää opiskelumotivaatiota, ja voi tuhota viimeisetkin opiskeluhalut.'
				},
				{
					type: 'p',
					content:
						'Kaikkein huonoin yhdistelmä on kontrolloimaton, pysyvä ja sisäinen attribuutio erityisesti epäonnistumisissa: “En ole koskaan osannut mitään, enkä tule ikinä oppimaan, koska olen vaan niin tyhmä, ja on ihan turha yrittää, kun ei siitä kuitenkaan tule mitään.”'
				},
				{
					type: 'p',
					content:
						'Attribuintityyleistä voi seurata niin sanottu itseään toteuttava ennuste. Kun opiskelija ajattelee etukäteen, ettei osaa, niin hänellä ei ole motivaatiota eikä jaksa tarttua kirjoihin. Tämä seurauksena tulokset myös heikkenevät, ja pahentavat kierrettä. Pahimmillaan tilanne voi johtaa opittuun avuttomuuteen: tilanteeseen, jossa opiskelijat pelkäävät epäonnistumista eivätkä jaksa edes yrittää. Kun kohtaat epäonnistumisia opinnoissa, voi olla mielenkiintoista hetki pohtia tapaa, jolla selität niitä itsellesi. Millaiset attribuutiotyylit ovat sinulle luontevia? Onko syy:'
				},
				{
					type: 'ul',
					content: [
						'omasta itsestä johtuva vai ulkopuolisista tekijöistä johtuva? (sisäinen vai ulkoinen)',
						'pysyvä vai väliaikainen?',
						'tilannekohtainen (kontrolloitava) vai kokonaisvaltainen (kontrolloimaton)'
					]
				},
				{
					type: 'p',
					content:
						'Kun opiskelija epäonnistuu koulussa, olisi hyödyllistä nähdä epäonnistumisen syy väliaikaisena, ulkopuolisista tekijöistä johtuvana ja kontrolloitavana. “Viime matikan koe meni tavallista huonommin, kokeita sattui olemaan siinä useita, enkä ehtinyt tällä kertaa valmistautua riittävästi.” '
				},
				{
					type: 'p',
					content:
						'Onnistumisen jälkeen olisi hyvä opetella ihmettelemään syitä siten, että näkisi oman menestymisen omasta itsestä johtuvaksi sekä pysyväksi. “Pärjään matikassa hienosti. Olen harjoitellut matematiikan tehtäviä paljon, pärjään matikassa hienosti!” Näin itseään toteuttava ennuste voi mennä toiseen, myönteiseen suuntaan, jolloin pienetkin onnistumisen kokemukset nostavat motivaatiota, jolloin aihekin voi osoittautua kiinnostavaksi. '
				}
			]
		},
		{
			id: 42,
			header: 'Tehtävä: ',
			description:
				'Oletko itse kokenut vastaavia tunteita eri kouluaineissa? Miten voisit muuttaa omia attribuointityylejäsi eri aineissa? ',
			placeholder: 'Kirjoita tähän...'
		},
		{
			id: 43,
			header: 'Tehtävä: Carol Dweck ja ajattelutavat ',
			description:
				'Käy katsomassa Carol Dweckin TED-talk video erilaisista ajattelutavoista. Millaisia eri ajattelutapoja nuorilla on? https://www.ted.com/talks/carol_dweck_the_power_of_believing_that_you_can_improve?language=fi',
			placeholder: 'Kirjoita tähän...'
		},
		{
			id: 44,
			header: 'Roolit ja ryhmä',
			text: [
				{
					type: 'p',
					content:
						'Ryhmässä syntyy rooleja. Rooli on ihmisen tapa olla ryhmässä ja sosiaalisessa vuorovaikutuksessa. Ihmisellä on elämässään monia erilaisia rooleja. Minä olen perheen äiti, vaimo, opettaja, ystävä, joissain ryhmissä johtaja, joissain ryhmissä tarkkailija. Rooli vaikuttaa paljon ihmisen toimintaan, koska siihen liittyy odotuksia ja ajatuksia. Pellen roolissa oleva henkilö käyttäytyy eri tavoin kuin johtajan roolissa oleva henkilö.'
				}
			]
		},
		{
			id: 45,
			header: 'Zimbardon vankilakoe',
			text:
				'Zimbardo tutki 1970-luvulla Stanfordin yliopistossa roolien vaikutusta ihmisen toimintaan. Hän laittoi täysin terveitä ja tavallisia nuoria miehiä koehenkilöinä kuviteltuun vankilaan. Tämä lavastettu vankila luotiin yliopiston kellariin. Koehenkilöitä oli 24. Osa koehenkilöistä sai vangin roolin, osa vanginvartijan roolin. Vangin roolin saaneet henkilöt pidätettiin ja vietiin käsiraudoissa vankilaan. Vanki sai nimekseen numeron, häntä ei enää kutsuttu omalla nimellään. Tällä tavalla roolin omaksumista vahvistettiiin. Vartijan roolin omaksumista vahvistettiin vartijan asulla, aurinkolaseilla. Kokeen oli tarkoitus jatkua kahden viikon ajan, mutta se jouduttiin keskeyttämään kuuden päivän kuluttua. Tutkimus keskeytettiin, koska vanginvartijoina toimivat nuoret koehenkilöt alkoivat kohdella vankeja huonosti. Annettu valta sekoitti joidenkin koehenkilöiden päät ja he käyttivät valtaa väärin. Katso video täältä: https://www.youtube.com/watch?v=sZwfNs1pqG0. Nuoret voivat esimerkiksi omaksua rooleja, joissa vallankäyttö on mahdollista. Kuten Zimbardon vankilakokeessa huomattiin, opiskelijan omaksuessa vanginvartijan roolin, alkoi hän käyttäytyä tämän roolin mukaisesti. Täysin mukavasta nuoresta miehestä tulikin heikomman kiusaaja. Mahdollisesti jollain nuorella voi olla syntynyt sellainen rooli, joka mahdollistaa toisten huonon kohtelun, esimerkiksi huutelun, määräilyn ja väkivallan ja näin kiusaaminen käynnistyy. Tärkeää on ymmärtää, että rooli ei ole ihmisen pysyvä ominaisuus vaan sitä voi muuttaa. Uudessa ryhmässä nuori voi saada uuden roolin, joka ei enää saa aikaan kiusaamista.'
		},
		{
			id: 46,
			header: 'Tehtävä: Zimbardon vankilakoe',
			description:
				'Voiko Zimbardon tutkimusta soveltaa arkisempaan ilmiöön, esimerkiksi koulukiusaamiseen? ',
			placeholder: 'Kirjoita tähän...'
		},
		{
			id: 47,
			header: 'Koulukiusaaminen ja roolit',
			text: [
				{
					type: 'p',
					content:
						'Nuoret voivat esimerkiksi omaksua rooleja, joissa vallankäyttö on mahdollista. Kuten Zimbardon vankilakokeessa huomattiin, opiskelijan omaksuessa vanginvartijan roolin, alkoi hän käyttäytyä tämän roolin mukaisesti. Täysin mukavasta nuoresta miehestä tulikin heikomman kiusaaja. Mahdollisesti jollain nuorella voi olla syntynyt sellainen rooli, joka mahdollistaa toisten huonon kohtelun, esimerkiksi huutelun, määräilyn ja väkivallan ja näin kiusaaminen käynnistyy. Tärkeää on ymmärtää, että rooli ei ole ihmisen pysyvä ominaisuus vaan sitä voi muuttaa. Uudessa ryhmässä nuori voi saada uuden roolin, joka ei enää saa aikaan kiusaamista.'
				}
			]
		},
		{
			id: 48,
			header: 'Konformisuus',
			text: [
				{
					type: 'p',
					content:
						'Miksi nuoret pukeutuvat mielellään samantyylisesti? Miksi porukassa nuori päätyy kokeilemaan tupakkaa tai päihteitä? Miksi opiskelija vastaa opettajan kysymykseen viikonlopun kuulumisista “joo, sama ku muillakin”? Miksi nuori päätyy ryhmän mukana naureskelemaan ja haukkumaan opiskelijatoveria koulussa? Konformisuus on ilmiö, jossa henkilö mukautuu ryhmän paineeseen. Tämä tarkoittaa, että ihminen toimii ja ajattelee kuten muutkin ympärillä olevat ihmiset. Ihminen helposti kuvittelee olevansa yksilö, joka toimii omien ajatustensa ohjaamana, mutta tutkimukset ovat osoittaneet, että meillä on taipumus yhdenmukaisuuteen eli konformisuuteen.'
				}
			]
		},
		{
			id: 49,
			header: 'Aschin janakoe',
			text:
				'Jo 1950-luvulla Solomon Asch laittoi koehenkilön lisäksi valekoehenkilöitä eli näyttelijöitä samaan tilaan. Heille kaikille näytettiin kolme eripituista janaa eli viivaa, ja näistä heidän piti valita jana, joka oli samanpituinen neljännen janan kanssa. Tämä tehtävä oli helppo koehenkilöille ja yksin ollessa virheitä sattui vähän. Koetilanteessa valekoehenkilöt antoivat väärän vastauksen tahallaan. Tutkimuksessa tutkittiin, mitä koehenkilö vastaa. Tutkimuksessa havaittiin, että 37 prosenttia vastauksista meni koehenkilöillä väärin, eli he vastasivat kuten muutkin ryhmässä. Koehenkilöt eivät halunneet olla erilaisia tai he olivat epävarmoja omasta havainnosta, joten he vastasivat kuten muutkin. Mikäli ryhmään lisättiin toinen aito koehenkilö, väärien vastausten määrä väheni paljon. Oli helpompi luottaa omiin ajatuksiin, kun ei ollut ainoa erilainen ryhmässä. Toki kaikki koehenkilöt eivät mukautuneet yhdenmukaisuuden paineeseen. Mikäli koehenkilö uskoi omaan itseensä, ryhmäpaineen vaikutus väheni.'
		},
		{
			id: 50,
			header: 'Normit ohjaavat käyttäytymistä',
			text: [
				{
					type: 'p',
					content:
						'Kuten Aschin viivakokeissa huomattiin, iso osa koehenkilöistä antoi vääriä vastauksia janan pituuden arviointitehtävään, koska kaikki muutkin koehenkilöt tekivät niin. Koulukiusaamista voidaan selittää ryhmäpaineella. Nuorten ryhmässä voi olla jäseniä, jotka aloittavat kiusaamisen ja muut seuraavat perässä, koska toisetkin tekevät niin. Ryhmän jäsenet alistuvat siis ryhmäpaineelle. Ilkeästä käyttäytymisestä on tällöin tullut normi eli ryhmän sääntö. Katso tästä video, jossa odotusaulussa koehenkilöt konformoituivat sosiaaliseen paineeseen https://www.youtube.com/watch?v=o8BkzvP19v4'
				}
			]
		},
		{
			id: 501,
			header: 'Monivalintatehtävä: konformisuus',
			btnText: 'Lähetä',
			parts: [
				{
					label: 'Konformisuus on ilmiö, jossa',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text:
								'henkilö tekee itsenäisiä ja vastuullisia päätöksiä',
							value: 'false'
						},
						{
							text: 'henkilö mukautuu ryhmän paineeseen',
							value: 'true'
						},
						{
							text:
								'henkilö ei osallistu ryhmän toimintaan millään tavalla',
							value: 'false'
						}
					]
					// correctAnswer: 'true'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 51,
			header: 'Milgramin sähköshokkikoe',
			text:
				'1960-luvulla Stanley Milgram teki kuuluisia tutkimuksia tottelevaisuudesta. Tottelevaisuus oli ajankohtainen ilmiö, koska toisen maailmansodan kauheuksia, juutalaisten teloituksia selitettiin tottelevaisuudella. Esimerkiksi holokaustin organisoija Adolf Eichman selitti toimintaansa siten, että hän vain totteli käskyjä. Milgram halusi tietää, mitä tavalliset ihmiset tekisivät, jos tutkija määräisi heitä antamaan sähköiskuja toiselle ihmiselle? Olisivatko he valmiita aiheuttamaan kipua toiselle ihmiselle auktoriteetin käskystä? Milgramin tutkimus tunnetaan nimellä sähköshokkikokeet. Sähköiskut eivät olleet kokeissa todellisia. Koehenkilö vain uskoi antavansa sähköiskuja tutkimusavustajalle.  Tutkimus toteutettiin siten, että koehenkilö uskoi osallistuvansa tutkimukseen, jossa tutkittaisiin rankaisemisen vaikutusta muistin toimintaan. Muistitehtäviä teki tutkimusavustaja eli hän näytteli oppijaa. Aina kun tutkimusavustaja vastasi muistitehtävään väärin, rankaisi koehenkilö häntä sähköiskulla. Tutkija eli kokeenjohtaja käski antaa sähköiskun väärästä vastauksesta. Tutkimuksessa tutkittiin sitä, että totteleeko koehenkilö tätä käskyä. Sähköiskuja ei siis oikeasti tapahtunut, tutkimusavustaja vain näytteli saavansa sähköiskun. Sähköiskut voimistuivat tutkimuksen aikana. Asiantuntijat ennustivat, että melkein kaikki koehenkilöt kieltäytyisivät tottelemasta kokeenjohtajaa, eivätkä antaisi sähköiskua kokeenjohtajan käskystä. Tottelevaisuuden voima oli kuitenkin yllättävä. Tutkimuksessa havaittiin, yli 60% koehenkilöistä oli valmiita antamaan voimakkaitakin sähköiskuja toiselle ihmiselle, mikäli auktoriteetti näin käski. Tämä tulos tuli koeasetelmassa, jossa koehenkilö ei nähnyt sähköiskuja saavaa tutkimusavustajaa, mutta kuuli hänen äänensä. Koehenkilö saattoi olla hyvin ahdistunut tässä tilanteessa, mutta yleensä hän kuitenkin totteli käskyä ja antoi sähköiskun. Eli kuka tahansa oli valmis vahingoittamaan toista ihmistä tietyssä tilanteessa, toisen satuttaminen ei siis vaatinut mitään sadistista luonnetta.'
		},
		{
			id: 52,
			header: 'Kiusaaminen ja tottelevaisuus',
			text: [
				{
					type: 'p',
					content:
						'Kiusaamistilanteessa voi olla kyse myös tottelevaisuudesta. Milgram tutki tätä ilmiötä sähköshokkikokeessaan ja huomasi, että mikäli auktoriteetti niin käskee, koehenkilöt olivat valmiita antamaan voimakkaitakin sähköiskuja toisille ihmisille. Nuorten joukossa voi olla siis käskyjä jakeleva pomo, joka saa muutkin ryhmän jäsenet kiusaamaan koulukaveriaan. Katso video, missä ohikulkijat tottelevat univormuun pukeutunutta miestä: https://www.youtube.com/watch?v=2ykbmBFqq54'
				}
			]
		},
		{
			id: 521,
			header: 'Monivalintatehtävä: Milgram',
			btnText: 'Lähetä',
			parts: [
				{
					label: 'Milgramin tutkimuksessa havaittiin, että',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text:
								'ihmiset eivät yleensä tottele johtajan käskyjä',
							value: 'false'
						},
						{
							text:
								'muilla ihmisillä ei ole merkitystä yksilön toiminnalle',
							value: 'false'
						},
						{
							text:
								'mikäli auktoriteetti niin käskee, koehenkilöt olivat valmiita antamaan voimakkaitakin sähköiskuja toisille ihmisille',
							value: 'true'
						}
					]
					// correctAnswer: 'true'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 53,
			header: 'Stereotypiat',
			text: [
				{
					type: 'p',
					content:
						'Sosiaalisissa tilanteissa meille syntyy sisäisiä malleja toisista ihmisistä.  Stereotypia on yleistys jostain ihmisryhmästä. Se voidaan tehdä jo muutaman esimerkin perusteella. Mieti hetki, millainen on mielestäsi suomalainen? Olet esimerkiksi tavannut suomalaisen, joka tykkää ruisleivästä ja sen perusteella voi syntyä käsitys, että kaikki suomalaiset tykkäävät syödä ruisleipää.'
				},
				{
					type: 'p',
					content:
						'Siskosi ei tahdo selvitä matematiikan tehtävistä ja sen perusteella voi syntyä käsitys, että kaikki tytöt ovat heikkoja matematiikassa. Yleistäminen helpottaa monimutkaisen maailman hahmottamista, mutta johtaa usein virheellisiin havaintoihin. Kaikki samaan ryhmään kuuluvat eivät ole samanlaisia. Stereotypioita on syytä kyseenalaistaa. Ne eivät ole totuuksia, vaan yksittäisen kokemuksen kautta syntyneitä yleistyksiä. Stereotypiat voivat johtaa syrjintään, mikäli jokin ihmisryhmä ja sen edustajat nähdään aina negatiivisessa valossa. Sukupuoleen liittyvät stereotypiat voivat vaikeuttaa esimerkiksi tasa-arvon toteutumista työelämässä. Tällaisia haitallisia stereotypioita ovat esimerkiksi “tytöt ovat heikompia matematiikassa kuin pojat”, “miehet ovat parempia johtajia kuin naiset”, “naiset ovat liian tunteellisia”.'
				},
				{
					type: 'p',
					content:
						'Stereotypiat voivat myös muuttaa yksilön käyttäytymistä. Henkilö voi alkaa käyttäytymään stereotypian mukaisesti ja siksi ne ovat vaarallisia. Tutkijat Aronson ja Steele halusivat tutkia tummaihoisten huonoa koulumenestystä Yhdysvalloissa 1990-luvulla. Rasistinen selitys tummaihoisten heikommalle koulumenestykselle oli se, että tummaihoiset olivat tyhmempiä. Aronson ja Steele jakoivat valko- ja tummaihoiset koehenkilöt kolmeen ryhmään. Koehenkilöille annettiin ongelmanratkaisua vaativia tehtäviä. Mutta vain yhdelle ryhmälle kerrottiin, että tutkimuksessa testattiin älykkyyttä. Tämä oli ainoa ryhmä, jossa valkoihoiset pärjäsivät tummaihoisia paremmin. Mikäli mustaihoiset eivät tienneet olevansa älykkyystestissä, heidän suorituksensa oli siis parempi. Tutkimuksessa toteutui stereotypiauhka eli stereotypian kohteena olevan ihmisen toiminta muuttuu stereotypian mukaiseksi, mikäli stereotypia aktivoidaan tilanteessa. Älykkyyttä mittaavassa tehtävässä henkilö, joka uskoo olevansa vähemmän älykkäämpi kuin muut, alisuoriutuu tehtävässä. Mieli täyttyy huolilla ja epäonnistumisen pelolla, ja suorituskyky heikkenee. Stereotypia tummaihoisten heikommasta älykkyydestä vaikutti siis tummaihoisten koulumenestykseen. Stereotypiasta tuli niin kutsuttu itseään toteuttava ennuste.'
				}
			]
		},
		{
			id: 54,
			header: 'Esimerkki tutkimussuunnitelmasta',
			text: [
				{
					type: 'p',
					content:
						'Olet tähän mennessä kurssilla tutustunut jo useisiin tieteellisiin tutkimuksiin, esimerkiksi Banduran bobo-nukke-kokeeseen, Pavlovin koirakokeeseen sekä Zimbardon vankilakokeeseen. Näiden tutkimusten avulla on hankittu tietoa ihmisen  toiminnasta. Psykologisia teorioita eli selitysmalleja ei kukaan ole keksinyt tyhjästä, vaan taustalla on johdonmukaista tieteellistä tutkimusta. Tutkimukseen liittyvät sanat voivat olla hankalia ymmärtää. Niinpä tarkastelemme näitä esimerkin kautta. '
				}
			]
		},
		{
			id: 54,
			header:
				'Tutkimusongelman määrittäminen: Miten älypuhelin vaikuttaa oppimistuloksiin?',
			text: [
				{
					type: 'p',
					content:
						'Jotta voidaan edes tutkia mitä tahansa ilmiötä, täytyy olla ensin selkeä kysymys, mihin etsitään vastauksia. Tutkimuksen tekeminen alkaa aina hyvästä kysymyksestä eli tutkimusongelman määrittelemisestä.'
				}
			]
		},
		{
			id: 55,
			header: 'Hypoteesi: Älypuhelin heikentää oppimistuloksia.',
			text: [
				{
					type: 'p',
					content:
						'Hypoteesi on ennuste tutkimustuloksista, jonka tutkija tekee aiemman tutkimustiedon varassa.'
				}
			]
		},
		{
			id: 56,
			header: 'Tutkimusote: kokeellinen',
			text: [
				{
					type: 'p',
					content:
						'Seuraavaksi tutkijan tulee miettiä, mikä on tutkimusote, eli  miten tutkimus toteutetaan. Tutkimusote voi olla kokeellinen tai ei-kokeellinen. Kokeellisessa tutkimuksessa  selvitetään syy-seuraussuhteita. Tässä tapauksessa voisimme käyttää kokeellista tutkimusotetta, koska haluamme selvittää älypuhelimen käytön vaikutusta oppimistuloksiin, eli syy - seuraussuhdetta oppimistuloksien kanssa. Eli vaikuttaako älypuhelimen käyttö oppitunneilla oppimistuloksiin? Muunlainen tutkimus on ei-kokeellista tutkimusta. Tässä kappaleessa käymme tarkemmin läpi nyt kokeellisen tutkimuksen toteuttamista.'
				}
			]
		},
		{
			id: 57,
			header: 'Muuttujien määrittely ja operationalisointi',
			text: [
				{
					type: 'p',
					content:
						'Muuttuja on se asia, jota halutaan tutkia. Tässä tapauksessa meillä on kaksi muuttujaa: älypuhelimen käyttö ja oppimistulokset. Näiden muuttujien välistä syy- seuraussuhdetta haluamme tutkia. Jotta näitä asioita voidaan tutkia, tulee ne muuttaa mitattavaan muotoon eli operationalisoida. Älypuhelimen käyttö muutetaan mitattavaan muotoon siten, että koehenkilöt asettavat älypuhelimensa pulpetilleen oppitunnin ajaksi ja saavat vapaasti käyttää sitä opetusta seuratessaan. Oppimistuloksia mitataan kokeella tunnin aiheesta. Eli opiskelijat tekevät oppitunnin päätteeksi kokeen. Koetuloksista saadaan arvo toiselle muuttujalle. Näin muuttujat on muutettu mitattavaan muotoon.'
				}
			]
		},
		{
			id: 571,
			header: 'Monivalintatehtävä: muuttja',
			btnText: 'Lähetä',
			parts: [
				{
					label: 'Tutkimuksessa muuttuja on ',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text: 'koehenkilö',
							value: 'false'
						},
						{
							text:
								'se asia, jota halutaan tutkia, esimerkiksi motivaatio',
							value: 'true'
						},
						{
							text: 'kontrolliryhmä',
							value: 'true'
						}
					]
					// correctAnswer: 'true'
					// tosin voit lisätä kommentoituna
				}
			]
		},
		{
			id: 58,
			header: 'Koehenkilöt: koeryhmä ja kontrolliryhmä',
			text: [
				{
					type: 'p',
					content:
						'Kokeellisessa tutkimuksessa olennaista on yrittää erottaa muuttujan vaikutus toiseen muuttujaan. Yleensä tutkimus rakennetaan siksi siten, että koehenkilöt jaetaan satunnaisesti koeryhmään ja kontrolliryhmään. Koeryhmä saa käyttää älypuhelinta oppitunnilla ja kontrolliryhmä ei saa käyttää älypuhelinta. Muilta osin ryhmien tulisi olla samanlaisia. Ainoa ero näiden ryhmien välillä saisi olla se kännykän käyttö. Mikäli ryhmien välillä sitten olisi eroa oppimistuloksissa, niin voitaisiin päätellä, että syy eroihin on älypuhelimen käytössä. Helppoa tällaisen tutkimuksen rakentaminen ei ole. Monet muutkin tekijät voivat vaikuttaa oppimistuloksiin. Esimerkiksi opiskelijoilla on erilaisia opiskelustrategioita tai toiseen ryhmään sattuu väsyneempiä opiskelijoita. Näitä häiritseviä tekijöitä tutkimuksessa kutsutaan häiriömuuttujiksi. Tutkijan on syytä niitä ihmetellä, koska ne voivat vääristää tutkimustulosta.'
				}
			]
		},
		{
			id: 59,
			header: 'Muuttujien määrittely',
			text: [
				{
					type: 'p',
					content:
						'Kokeellisessa tutkimuksessa nimetään riippumaton ja riippuva muuttuja. Riippumaton muuttuja on se, jota tutkija muuttelee ryhmien välillä ja jonka vaikutusta toiseen muuttujaan halutaan selvittää. Tässä tapauksessa älypuhelimen käyttö on riippumaton muuttuja. Riippuva muuttuja on mittaamisen kohteena eli tässä tapauksessa oppimistulokset.'
				}
			]
		},
		{
			id: 60,
			header: 'Tiedonkeruumenetelmä',
			text: [
				{
					type: 'p',
					content:
						'Tietoa voi kerätä monella eri tavalla. Havainnointi, kyselyt, haastattelu, itsearviointi, testit ja aivokuvantamismenetelmät ovat tapoja hankkia tietoa tutkittavasta aiheesta eli tiedonkeruumenetelmiä. Tässä tapauksessa älypuhelimen käytöstä hankitaan tietoa havainnoimalla ja oppismistuloksista opittua testaamalla kokeen avulla. '
				}
			]
		},
		{
			id: 61,
			header: 'Tutkimuksen arviointi',
			text: [
				{
					type: 'p',
					content:
						'Kun tutkimus on toteutettu, se julkaistaan muiden tutkijoiden arvosteltavaksi. Tieteellisen tutkimuksen on oltava luotettava (reliabiliteetti) ja pätevä (validiteetti). Tutkimus on luotettava, jos sen tulokset voidaan toistaa muissa tutkimuksissa. Tutkimus on pätevä, mikäli tutkimuksessa onnistutaan mittaamaan juuri sitä mitä halutaan. Eli tutkijan on syytä tarkastella, että mittaako tutkimus juuri sitä, mitä halutaan mitata. Tutkimuksen pätevyys eli validiteetti on hyvä, mikäli esimerkiksi motivaatiotutkimus mittaa nimenomaan motivaatiota eikä vaikka vireystilaa.'
				}
			]
		},
		{
			id: 63,
			header: 'Otsikko',
			text: [
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo.'
				},
				{
					type: 'ul',
					content: [
						'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.',
						'Aliquam tincidunt mauris eu risus.',
						'Vestibulum auctor dapibus neque.'
					]
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.'
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue, eu vulputate magna eros eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan porttitor, facilisis luctus, metus'
				}
			]
		},
		{
			id: 64,
			header: 'Otsikko',
			description: 'Kootut selitykset'
			// tähän voi lisätä accept: '.jpg, .png., .gif' tai jotain
		},
		{
			id: 65,
			header: 'Otsikko',
			text: [
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo.'
				},
				{
					type: 'ul',
					content: [
						'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.',
						'Aliquam tincidunt mauris eu risus.',
						'Vestibulum auctor dapibus neque.'
					]
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.'
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue, eu vulputate magna eros eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan porttitor, facilisis luctus, metus'
				}
			]
		}
	]
})

export const getters = {
	contentById: state => id => {
		return state.list.find(item => item.id === id)
	},
	contentBySection: state => data => {
		const content = []
		for (let i = 0; i < data.length; i++) {
			const id = data[i].contentId
			content.push(state.list.find(x => x.id === id))
		}
		return content
	},
	fetchContent: state => data => {
		return state.list.filter(x => data.some(y => y.contentId === x.id))
	},
	contentByType: state => type => {
		let filters = []
		if (type === true) {
			filters = ['TheoryElement', 'SpecialText', 'VideoEmbed']
		} else {
			filters = ['Assignment', 'MultipleChoice', 'ReturnAssignment']
		}
		return state.list.filter(x => filters.some(y => y === x.type))
	}
}
