from cgi import print_arguments
import json, math, requests, os, argparse
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from stix2 import MemoryStore, Filter
 
#WhoIsWhoAPT 1.0 19/09/2022. Credits: Javier Muñoz

colour1 = '#a1d99b'
colour2 = '#4597c8'
colour3 = '#a644b1'

aptnames = []
compRes = {}
datadirname = os.path.dirname(__file__) + "\\resources\\data"

def get_data_from_branch(domain):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

def similarity(c1, c2):
    terms = set(c1).union(c2)
    dotprod = sum(c1.get(k, 0) * c2.get(k, 0) for k in terms)
    magA = math.sqrt(sum(c1.get(k, 0)**2 for k in terms))
    magB = math.sqrt(sum(c2.get(k, 0)**2 for k in terms))
    return dotprod / (magA * magB)

def listTtpxApt(thesrc):
    groups = thesrc.query([ Filter("type", "=", "intrusion-set") ])
    result = {}
    for element in groups:
        aptnames.append(element.name)
        tacticasapt = []
        relationships = thesrc.query([ Filter("type", "=", "relationship"),
        Filter("source_ref", "=", element.id)
        ])
        for relation in relationships:
            attackPattern = thesrc.query([ Filter("type", "=", "attack-pattern"),
        	Filter("id", "=", relation.target_ref),
        	])
            if attackPattern:
                if ('x_mitre_deprecated' in attackPattern[0]):  
                    if not (attackPattern[0]['x_mitre_deprecated']== True):  
                        ttptypetec = [(attackPattern[0]['external_references'][0]['external_id']), (attackPattern[0]['kill_chain_phases'][0]['phase_name']) ]
                        tacticasapt.append(ttptypetec)		
                else:
                    ttptypetec = [(attackPattern[0]['external_references'][0]['external_id']), (attackPattern[0]['kill_chain_phases'][0]['phase_name']) ]
                    tacticasapt.append(ttptypetec)
        result[element.name] = tacticasapt
    os.makedirs(datadirname, exist_ok=True)
    with open (datadirname + '\\ttpsMitre.txt', "w+") as f:
        f.write(json.dumps(result))
    return result

def comparationJsonApts(group, compApt):
    b0 = group.get(compApt)
    unzippeda0 = list(zip(*b0))
    b1 = Counter(set(unzippeda0[0]))
    for apt in group:
            if group[apt]:
                a0 = group.get(apt)
                unzippeda0 = list(zip(*a0))
                a1 = Counter(set(unzippeda0[0]))
                # Deprecated json load
                # with open(os.path.dirname(__file__)+ '\\' + sys.argv[1]) as f:
                #     techdata = json.load(f) ['techniques']
                # loadedTech = []
                # for x in techdata:
                #     loadedTech.append(x['techniqueID'])
                # b1 = Counter(set(loadedTech))
                result = similarity(a1, b1)
                compRes[apt] = round(result, 5)
    sortedCompRes = sorted(compRes.items(), key=lambda x: x[1], reverse=True)
    blankList = []
    for x in sortedCompRes[1:16]:
        blankList.append(list(x))
    for idx, y in enumerate(blankList):
        x0 = group.get(y[0])
        unzippedx0 = list(zip(*x0))
        x1 = len((set(unzippedx0[0])))
        x2 = Counter(set(unzippedx0[0]))
        terms = len(set(x2).intersection(b1))
        fractionString = "{}/{}".format(terms, x1)
        blankList[idx] = (y[0], y[1], fractionString)
        
        
    print(pd.DataFrame(blankList,columns=['Group Name','Similarity','Ttps Covert']))
    df = pd.DataFrame(list(sortedCompRes[1:16]),columns=['Group Name','Similarity'])
    df.plot(x ='Group Name', y='Similarity', kind = 'bar')
    plt.tight_layout()
    plt.show()
    exit()

def addCustomtoTtpsMitre(ttpsmitre):
    customApt = {} 
    for filename in os.listdir(os.path.dirname(__file__) + "\\resources"):
        if filename.endswith('.json'):
            with open(os.path.dirname(__file__) + "\\resources\\" + filename) as f:
                data = json.load(f)
                techdata =  data ['techniques']
                loadedName = data ['name']
            loadedTech = []
            
            for x in techdata:
                if x['color']:
                    ttptypetec = [x['techniqueID'], x['tactic']]
                    loadedTech.append(ttptypetec)
            customApt[loadedName] = loadedTech
    return (ttpsmitre | customApt)

tecnicas= []

data = {
    "name": "placeholder",
	"versions": {
		"attack": "11",
		"navigator": "4.6.5",
		"layer": "4.3"
	},
	"domain": "enterprise-attack",
	"description": "",
	"filters": {
		"platforms": [
			"Linux",
			"macOS",
			"Windows",
			"PRE",
			"Containers",
			"Network",
			"Office 365",
			"SaaS",
			"Google Workspace",
			"IaaS",
			"Azure AD"
		]
	},
	"sorting": 0,
	"layout": {
		"layout": "side",
		"aggregateFunction": "average",
		"showID": False,
		"showName": True,
		"showAggregateScores": False,
		"countUnscored": False
	},
	"hideDisabled": False,
	"techniques": tecnicas,
	"gradient": {
		"colors": [
			"#ff6666ff",
			"#ffe766ff",
			"#8ec843ff"
		],
		"minValue": 0,
		"maxValue": 100
	},
	"legendItems": [],
	"metadata": [],
	"links": [],
	"showTacticRowBackground": False,
	"tacticRowBackground": "#dddddd",
	"selectTechniquesAcrossTactics": True,
	"selectSubtechniquesWithParent": False
}
def creacionJson(group, apt, col1):
	a1 = group.get(apt)
	for x in a1:
		var = {
				"techniqueID": "placeholder",
				"tactic": "placeholder",
				"color": col1,
				"comment": "",
				"enabled": True,
				"metadata": [],
				"links": [],
				"showSubtechniques": False
	}
		var["techniqueID"] = x[0]
		var["tactic"] = x[1]
		tecnicas.append(var)
		docName = "{}".format(apt)
		data['name'] = docName
	with open(os.path.dirname(__file__) + "\\" + docName + ".json", "w") as write_file:
		json.dump(data, write_file, indent=4)

def creacionJsoncomparenoJson(apt1, apt2, group, col1, col2, col3):
    a1 = group.get(apt1)

    a2 = group.get(apt2)

    ttpsa1 = []
    ttpsa2 = []
    ttpsa3 = []

    for i in a1:
        if i in a2:
            ttpsa3.append(i)
        else:
            ttpsa1.append(i)
    for i in a2:
        if i not in a1:
            ttpsa2.append(i)


    for x in ttpsa1:
        var = {
                "techniqueID": "placeholder",
                "tactic": "placeholder",
                "color": col1,
                "comment": "",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
	}
        var["techniqueID"] = x[0]
        var["tactic"] = x[1]
        tecnicas.append(var)
    for x in ttpsa2:
        var = {
                "techniqueID": "placeholder",
                "tactic": "placeholder",
                "color": col2,
                "comment": "",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
	}
        var["techniqueID"] = x[0]
        var["tactic"] = x[1]
        tecnicas.append(var)
    for x in ttpsa3:
        var = {
                "techniqueID": "placeholder",
                "tactic": "placeholder",
                "color": col3,
                "comment": "",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
	}
        var["techniqueID"] = x[0]
        var["tactic"] = x[1]
        tecnicas.append(var)
        docName= "{} vs {}".format(apt1, apt2)
        data['name'] = docName
    with open(os.path.dirname(__file__) + "\\" + docName + ".json", "w") as write_file:
        json.dump(data, write_file, indent=4)

#****************************************************************************************************************************************

parser = argparse.ArgumentParser('WhoIsWhoAPT', description='WhoIsWhoAPT', usage= 'python whoiswhoapt.py [-c <APT>] | [-l <APT>] | [-v <APT1> <APT2>] [-col <APT1 Color> <APT2 Color> <Match Color>]', epilog='Credits: Javier Muñoz')
parser.add_argument('-c', '--compare', help='Compare an APT with all the others APTs', nargs=1, metavar= 'APT')
parser.add_argument('-v', '--versus', help='Compare two APTs and extract the comparison matrix', nargs=2, metavar= ('APT', 'APT2'))
parser.add_argument('-l', '--layer', help='Create a layer with selected APT\'s TTPs', nargs=1, metavar= 'APT')
parser.add_argument('-col', '--colours', help='Choose the colors with which the data will be represented in the layer. Most be a color hexcode.', nargs='+')
args = parser.parse_args()


if os.path.exists(datadirname + '\\ttpsMitre.txt'):
    ttpsMitre = json.load(open(datadirname + '\\ttpsMitre.txt'))
    
else: 
    print('APT database not found. Downloading...')
    src = get_data_from_branch("enterprise-attack")
    print('Database downloaded')
    ttpsMitre = listTtpxApt(src)

completeApt = addCustomtoTtpsMitre(ttpsMitre)

if args.versus and (args.compare or args.layer):
    print('Options Versus, Compare and Layer are mutually exclusive, you can only choose one per execution')
elif args.compare and (args.versus or args.layer):
    print('Options Versus, Compare and Layer are mutually exclusive, you can only choose one per execution')
elif args.compare:
    comparationJsonApts(completeApt, args.compare[0])
elif args.layer:
    if args.colours:
        creacionJson(completeApt, args.layer[0], args.colours[0])
        print(args.layer[0], 'layer created')
        exit()
    creacionJson(completeApt, args.layer[0], colour1)
    print(args.layer[0], 'layer created')
    exit()
elif args.versus:
    if args.colours and (len(args.colours) == 3):
        creacionJsoncomparenoJson(args.versus[0], args.versus[1], completeApt, args.colours[0], args.colours[1], args.colours[2])
        print(args.versus[0], 'vs', args.versus[1], 'layer created')
        exit()
    elif args.colours: 
        print("With VERSUS you need to specify 3 colous")
        exit()
    creacionJsoncomparenoJson(args.versus[0], args.versus[1], completeApt, colour1, colour2, colour3)
    print(args.versus[0], 'vs', args.versus[1], 'layer created')
    exit()
#help
else:
    parser.print_help()

exit()

