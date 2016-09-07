from __future__ import absolute_import, print_function, unicode_literals
from charm.config import libs, pairing_lib

a = """type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1"""

a1 = """type a1
p 48512875896303752499712277254589628516419352188294521198189567511009073158115045361294839347099315898960045398524682007334164928531594799149100548036445760110913157420655690361891290858441360807158247259460501343449199712532828063940008683740048500980441989713739689655610578458388126934242630557397618776539259
n 36203638728584889925158415861634051131656232976339194924022065306723188923966451762160327870969638730567198058600508960697138006366861790409776528385407283664860565239295291314844246909284597617282274074224254733917313218308080644731349763985110821627195514711746037056425804819692632040479575042834043863089
l 1340
"""

d159 = """type d
q 625852803282871856053922297323874661378036491717
n 625852803282871856053923088432465995634661283063
h 3
r 208617601094290618684641029477488665211553761021
a 581595782028432961150765424293919699975513269268
b 517921465817243828776542439081147840953753552322
k 6
nk 60094290356408407130984161127310078516360031868417968262992864809623507269833854678414046779817844853757026858774966331434198257512457993293271849043664655146443229029069463392046837830267994222789160047337432075266619082657640364986415435746294498140589844832666082434658532589211525696
hk 1380801711862212484403205699005242141541629761433899149236405232528956996854655261075303661691995273080620762287276051361446528504633283152278831183711301329765591450680250000592437612973269056
coeff0 472731500571015189154958232321864199355792223347
coeff1 352243926696145937581894994871017455453604730246
coeff2 289113341693870057212775990719504267185772707305
nqr 431211441436589568382088865288592347194866189652
"""

d201 = """type d
q 2094476214847295281570670320144695883131009753607350517892357
n 2094476214847295281570670320143248652598286201895740019876423
h 1122591
r 1865751832009427548920907365321162072917283500309320153
a 9937051644888803031325524114144300859517912378923477935510
b 6624701096592535354217016076096200573011941585948985290340
k 6
nk 84421409121513221644716967251498543569964760150943970280296295496165154657097987617093928595467244393873913569302597521196137376192587250931727762632568620562823714441576400096248911214941742242106512149305076320555351603145285797909942596124862593877499051211952936404822228308154770272833273836975042632765377879565229109013234552083886934379264203243445590336
hk 24251848326363771171270027814768648115136299306034875585195931346818912374815385257266068811350396365799298585287746735681314613260560203359251331805443378322987677594618057568388400134442772232086258797844238238645130212769322779762522643806720212266304
coeff0 362345194706722765382504711221797122584657971082977778415831
coeff1 856577648996637037517940613304411075703495574379408261091623
coeff2 372728063705230489408480761157081724912117414311754674153886
nqr 279252656555925299126768437760706333663688384547737180929542
"""

d224 = """type d
q 15028799613985034465755506450771565229282832217860390155996483840017
n 15028799613985034465755506450771561352583254744125520639296541195021
h 1
r 15028799613985034465755506450771561352583254744125520639296541195021
a 1871224163624666631860092489128939059944978347142292177323825642096
b 9795501723343380547144152006776653149306466138012730640114125605701
k 6
nk 11522474695025217370062603013790980334538096429455689114222024912184432319228393204650383661781864806076247259556378350541669994344878430136202714945761488385890619925553457668158504202786580559970945936657636855346713598888067516214634859330554634505767198415857150479345944721710356274047707536156296215573412763735135600953865419000398920292535215757291539307525639675204597938919504807427238735811520
hk 51014915936684265604900487195256160848193571244274648855332475661658304506316301006112887177277345010864012988127829655449256424871024500368597989462373813062189274150916552689262852603254011248502356041206544262755481779137398040376281542938513970473990787064615734720
coeff0 11975189258259697166257037825227536931446707944682470951111859446192
coeff1 13433042200347934827742738095249546804006687562088254057411901362771
coeff2 8327464521117791238079105175448122006759863625508043495770887411614
nqr 142721363302176037340346936780070353538541593770301992936740616924
"""

# Notes: pbc library parameters : SS means super singular curve with the following digits 
# represents the size of the base field in bits. MNT curves were created by 
# Miyaji, Nakabayashi and Takano. BN curve was created by Barreto and Naehrig
params = None
if pairing_lib == libs.pbc:
   params = {'SS512':a, 'SS1024':a1, 'MNT159':d159, 'MNT201':d201, 'MNT224':d224 }
elif pairing_lib == libs.miracl:
   params = {'MNT160':80, 'BN256':128, 'SS512':80, 'SS1536':128}
elif pairing_lib == libs.relic:
   params = {'BN158':0, 'BN254':1, 'BN256':2}

