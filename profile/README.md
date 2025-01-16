
# Overview

```mermaid
flowchart TB
    %% Diagram direction: top-to-bottom (TB)

    %% Point of Interaction
    subgraph Point of Interaction
        user((User))
        github((Automation via GitHub))
    end

    %% User Scenarios
    subgraph User Scenarios
        cweInteractively[Interactively Assign CWEs]
        cvePublish[Interactively populate CVE fields for CVE Publication]
        bulkAssign[Bulk Assign CWEs]
    end

    %% Solutions
    subgraph Solutions
        cweExpert[CWE Expert<br/>NotebookLM Gemini Pro Free]
        cweCvePublisher[CVE CWE Oracle]
        bulkAssignSolution[Bulk Assign CWEs]
    end

    %% Building Blocks
    subgraph Building Blocks
        getContent[Get CVE Content<br/>Source of Truth]
        findDuplicates[Find CVE Description Duplicates]
        getKeyphrases[Get CVE Vulnerability Keyphrases]
        extractKeyphrases[Extract CVE Vulnerability Keyphrases<br/>Gemini 1.5 Flash FineTuned $10]
        assignImpact[Assign MITRE Technical Impact<br/>Gemini 1.5 Flash FineTuned $10]
        getReferences[Get CVE References Content]
        getReferencesCrawler[Get CVE References Crawler<br/>Gemini 2.0 Flash Experimental $0]
        createVulnDesc[Create Vulnerability Description<br/>PoC. Any LLM]
        checkQuality[Check Vulnerability Description quality]
        KeyPhraseExtractionModel[KeyPhrase Extraction Model]
        KeyPhraseExtractionModelAnalyzer[KeyPhrase Extraction Model Analyzer<br>to evaluate, and change, the model output]

    end

    %% Connections between sections

    github --> bulkAssign
    user --> cweInteractively
    user --> cvePublish

    cvePublish --> cweCvePublisher
    cweCvePublisher --> createVulnDesc
    cweCvePublisher --> checkQuality
    checkQuality --> getKeyphrases


    cweInteractively --> cweExpert
    bulkAssign --> bulkAssignSolution
    bulkAssignSolution --> getContent
    bulkAssignSolution --> getKeyphrases
    bulkAssignSolution --> getReferences
    bulkAssignSolution --> assignImpact
    assignImpact --> extractKeyphrases
    getReferences --> getReferencesCrawler
    getKeyphrases --> extractKeyphrases
    extractKeyphrases --> KeyPhraseExtractionModel
    extractKeyphrases --> KeyPhraseExtractionModelAnalyzer

    %% Styling
    style cweCvePublisher fill:#d3d3d3,stroke:#000,stroke-width:2,stroke-dasharray:5 5
    style createVulnDesc fill:#d3d3d3,stroke:#000,stroke-width:2,stroke-dasharray:5 5

    %% Clickable links (replace with your URLs)
    click cweInteractively "https://github.com/CyberSecAI#create-a-cwe-expert-interactively-assign-cwes" "Interactively Assign CWEs" _blank
    click vulnDesc "https://github.com/CyberSecAI#create-vulnerability-description-from-advisory-patch-and-other-existing-vulnerability-information" "Create Vulnerability Description" _blank
    click checkQuality "https://github.com/CyberSecAI/VulnerabilityDescriptionQualityChecker" "Check Vulnerability Description quality" _blank
    click impact "https://example.com/impact-and-rootcause" "Understand Vulnerability Impact, Rootcause..." _blank
    click bulkAssign "https://github.com/CyberSecAI#bulk-assign-cwes" "Bulk Assign CWEs" _blank

    click cweExpert "https://github.com/CyberSecAI/CWE-Expert" "CWE Expert Tool" _blank
    click createVulnDesc "https://github.com/CyberSecAI#create-vulnerability-description-from-advisory-patch-and-other-existing-vulnerability-information" "Vulnerability Description Tool" _blank
    click checkDescQuality "https://github.com/CyberSecAI#create-vulnerability-description-from-advisory-patch-and-other-existing-vulnerability-information" "Check Description Quality Tool" _blank
    click bulkAssignSolution "https://github.com/CyberSecAI/top25_cwe_assign_compare" "Bulk Assign Solution Tool" _blank

    click getContent "https://github.com/CyberSecAI/cve_source_of_truth" "Get CVE Content" _blank
    click findDuplicates "https://github.com/CyberSecAI/cve_dedup" "Find CVE Duplicates" _blank
    click extractKeyphrases "https://github.com/CyberSecAI/cve_info" "Extract Keyphrases Tool" _blank
    %% click assignImpact "https://example.com/assign-impact" "Assign MITRE Technical Impact Tool" _blank
    click getReferences "https://github.com/CyberSecAI/cve_info_refs" "Get CVE References" _blank
    click getReferencesCrawler "https://github.com/CyberSecAI/cve_info_refs_crawler" "Get CVE References" _blank
    click KeyPhraseExtractionModel "https://github.com/CyberSecAI/KeyPhraseExtractionModel" "KeyPhrase Extraction Model" _blank
    click KeyPhraseExtractionModelAnalyzer "https://github.com/CyberSecAI/keyphrase_analyzer" "KeyPhrase Extraction Model" _blank
````

# CVE Enrichment User Scenarios

- [CVE Enrichment User Scenarios](#cve-enrichment-user-scenarios)
  - [Extract Key Phrases from Vulnerability Description](#extract-key-phrases-from-vulnerability-description)
    - [Solution](#solution)
    - [Background](#background)
    - [Narrative](#narrative)
      - [Pre-Narrative (how things are now)](#pre-narrative-how-things-are-now)
      - [Post-Narrative (how we want things to be in the future - aspirational)](#post-narrative-how-we-want-things-to-be-in-the-future---aspirational)
  - [Create Vulnerability Description from Advisory, Patch, and other existing vulnerability information](#create-vulnerability-description-from-advisory-patch-and-other-existing-vulnerability-information)
    - [Solution Proof Of Concept](#solution-proof-of-concept)
    - [Background](#background-1)
    - [Narrative](#narrative-1)
      - [Pre-Narrative (how things are now)](#pre-narrative-how-things-are-now-1)
      - [Post-Narrative (how we want things to be in the future - aspirational)](#post-narrative-how-we-want-things-to-be-in-the-future---aspirational-1)
  - [Rate Vulnerability Description Quality](#rate-vulnerability-description-quality)
    - [Solution](#solution-1)
    - [Background](#background-2)
      - [How much information is in the Vulnerability Description](#how-much-information-is-in-the-vulnerability-description)
      - [General Vulnerability Description Quality Issues](#general-vulnerability-description-quality-issues)
        - [CVEProject/cvelistV5/issues/ related to Quality](#cveprojectcvelistv5issues-related-to-quality)
    - [Narrative](#narrative-2)
      - [Pre-Narrative (how things are now)](#pre-narrative-how-things-are-now-2)
      - [Post-Narrative (how we want things to be in the future - aspirational)](#post-narrative-how-we-want-things-to-be-in-the-future---aspirational-2)
  - [Bulk Assign CWEs](#bulk-assign-cwes)
    - [Solution Proof Of Concept](#solution-proof-of-concept-1)
    - [Background](#background-3)
    - [Narrative](#narrative-3)
      - [Pre-Narrative (how things are now)](#pre-narrative-how-things-are-now-3)
      - [Post-Narrative (how we want things to be in the future - aspirational)](#post-narrative-how-we-want-things-to-be-in-the-future---aspirational-3)
  - [Create a CWE Expert: Interactively Assign CWEs](#create-a-cwe-expert-interactively-assign-cwes)
    - [Solution](#solution-2)
    - [Background](#background-4)
    - [Narrative](#narrative-4)
      - [Pre-Narrative (how things are now)](#pre-narrative-how-things-are-now-4)
      - [Post-Narrative (how we want things to be in the future - aspirational)](#post-narrative-how-we-want-things-to-be-in-the-future---aspirational-4)
- [User Stories](#user-stories)
  - [Bulk Check CWEs](#bulk-check-cwes)
  - [CVE Description Duplicates](#cve-description-duplicates)
- [Repo Overview](#repo-overview)






## Extract Key Phrases from Vulnerability Description 

### Solution

> [!TIP]
> See https://github.com/CyberSecAI/cve_info.
>  
> For a given CVE Description, the following is available in the json file for that CVE:
> - description: original CVE Description
> - keyphrases: Vulnerability Key Phrases extracted from the CVE Description per https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf
> - Optional: mitre_technical_impacts: The Impact(s) mapped to MITRE Technical Impacts per https://cwe.mitre.org/community/swa/priority.html

### Background 
Vulnerability Descriptions should use [Key Details Phrasing](https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf) because _"the correct amount and type of information in a description is important"._

There are many use cases associated with using this Vulnerability Description:
1. Assigning other CVE data e.g. CWE, CPE, ....
2. Data Analysis and research to determine salient characteristics or trends 

Vulnerability Descriptions range significantly in quality, and there are even descriptions that have no vulnerability information.

### Narrative 

#### Pre-Narrative (how things are now)

Where Key Phrases from Vulnerability Description are extracted, this tends to be done adhoc, in isolation, using a variety of tools from RegEx to Language Models.
This data is not publicly available or shared.


#### Post-Narrative (how we want things to be in the future - aspirational)

For all CVEs, the Key Phrases from Vulnerability Description are available in a repository that
1. is publicly available
2. is consistent format
3. allows feedback and updating
4. is accurate i.e. the Key Phrases are correct for the Vulnerability Description

This increases the quality of Vulnerability Descriptions, and the associated data derived from them.


## Create Vulnerability Description from Advisory, Patch, and other existing vulnerability information

### Solution Proof Of Concept

> [!TIP]
> See https://github.com/orgs/CyberSecAI/projects/2/views/1?pane=issue&itemId=86534944&issue=CyberSecAI%7CCWEMap%7C34 comments for Proof Of Concept demo examples of creating a CVE vulnerability Description from a set of links.

### Background
Currently, in general, Vulnerability Descriptions are generated manually - and often lack quality and consistency.

MITRE CVE prescribe Description formats https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf.

https://vulnogram.github.io/#editor encourages/supports this in CVE Description:

[PROBLEMTYPE] in [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] on [PLATFORMS] allows [ATTACKER] to [IMPACT] via [VECTOR] 

Broadly, there's 2 approaches:

1. user provides reference links and any info they already have. A tool generates the content for the CVE description and other fields (using whatever format) and it has quality baked in - and a user reviews/tweaks as required.
2. user fills in the fields manually (using whatever format), and a tool checks.

Notes
1. Reducing human/manual effort would be my overall approach to improving CVE enrichment i.e. approach 1.
2. This relates to extracting data from CVE reference links to inform CWE, and KeyPhrase, MITRE Technical Impact.

### Narrative 

#### Pre-Narrative (how things are now)
A user, based on their understanding of the vulnerability, and what makes a good vulnerability description, manually writes the Vulnerability Description.

#### Post-Narrative (how we want things to be in the future - aspirational)

For all CVEs, the Vulnerability Descriptions
1. follow the [template](https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf)
2. are current, complete, correct
3. can be auto-generated from existing advisory and patch information per [Proof Of Concept](https://github.com/orgs/CyberSecAI/projects/2/views/1?pane=issue&itemId=86534944&issue=CyberSecAI%7CCWEMap%7C34).
4. can be auto-reviewed and rated for quality

It should be easy for users to do the right thing i.e. the easy path gives the best result. The easy path is to auto create good Vulnerability Descriptions from the 
- existing advisory and patch information per [Proof Of Concept](https://github.com/orgs/CyberSecAI/projects/2/views/1?pane=issue&itemId=86534944&issue=CyberSecAI%7CCWEMap%7C34).
- user supplied info




## Rate Vulnerability Description Quality

### Solution

> [!TIP]
> See https://github.com/CyberSecAI/VulnerabilityDescriptionQualityChecker for an analyis of how much information is in Vulnerability Descriptions; specifically [Key Details Phrases](https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf) present.

### Background

Vulnerability Description Quality can be rated by:
#### How much information is in the Vulnerability Description 
What [Key Details Phrases](https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf) are present e.g. 
   
   1. https://nvd.nist.gov/vuln/detail/cve-2024-45346#VulnChangeHistorySection original version has no vulnerability information:
      > "The Xiaomi Security Center expresses heartfelt thanks to Ken Gannon and Ilyes Beghdadi of NCC Group working with Trend Micro Zero Day Initiative! At the same time, we also welcome more outstanding and professional security experts and security teams to join the Mi Security Center (MiSRC) to jointly ensure the safe access of millions of Xiaomi users worldwide Life."
   2. Only Impact: https://nvd.nist.gov/vuln/detail/CVE-1999-0015:
      >"Teardrop IP denial of service."
   3. Product and Weakness: 
      1. https://nvd.nist.gov/vuln/detail/CVE-2022-23264
          > Microsoft Edge (Chromium-based) Spoofing Vulnerability
      2. https://nvd.nist.gov/vuln/detail/CVE-2022-21904
          > Windows GDI Information Disclosure Vulnerability        
#### General Vulnerability Description Quality Issues
   1. Having only characters from a specified character set e.g. ASCII or UTF-8.  
   2. Containing HTML Tags
      1. e.g. there are 686 `<p> and </p>` tag pairs, mostly in CVE-2020- CVES, mostly in MicroSoft CVEs
      2. e.g. there are 10  `<strong> and </strong>` tag pairs
   3. Typos, Spelling and grammar issues.
   4. JSON Schema Conformance issues



#####  [CVEProject/cvelistV5/issues/](https://github.com/CVEProject/cvelistV5/issues/56) related to Quality
1. https://github.com/CVEProject/cvelistV5/issues/5 "118955 CVE records don't have an affected product/vendor or version"
   1. > 118955 records have not a valid affected software in their details. With some random picks to verify, the software is only noted down in the descriptions[] fields as text, but are not set inside the containers/cna/affected Array inside the JSON file.
2. https://github.com/CVEProject/cvelistV5/issues/64 "A large number of CVEs do not have products and versions"
   1. >A large number of CVEs do not have products and versions, but corresponding versions such as fastjson can be found on the CVE website
3. https://github.com/CVEProject/cvelistV5/issues/19 ""opertion" misspelling"
4. https://github.com/CVEProject/cvelistV5/issues/56 "HTML tag inside json"

  
### Narrative 

#### Pre-Narrative (how things are now)

Vulnerability Description Quality is largely a manual effort - both at Vulnerability Description creation time and CVE publication time.

#### Post-Narrative (how we want things to be in the future - aspirational)

A rating of the quality of CVE Descriptions is applied 
- if a Vulnerability Description does not meet some minimum standard, then it is flagged.
- the quality issues are listed
- an overall score is given

Users can immediately determine if their CVE Description meets the required quality rating.

Low Quality Vulnerability Descriptions are eradicated from published CVEs by
1. Detecting Low Quality Vulnerability Descriptions 
2. Rejecting Low Quality Vulnerability Descriptions 






## Bulk Assign CWEs

### Solution Proof Of Concept

> [!TIP]
> See https://github.com/cisagov/vulnrichment/issues?q=is%3Aissue%20state%3Aclosed%20author%3ACrashedmind for some auto-generated CWE assignment examples for CISA Vulnrichment.
>
> These include 
> - CVE Description extracted KeyPhrases
> - supporting examples of similar CVEs from the MITRE CWE Observed Examples, and MITRE CWE Top 25 examples
> - Assigned CWE with the CWE mapping meta data 


### Background 


Per [CWE Guidance](https://cwe.mitre.org/documents/cwe_usage/guidance.html)
> Root cause mapping is the identification of the underlying cause(s) of a vulnerability. This is best done by correlating CVE Records and/or bug or vulnerability tickets with CWE entries. Today, this is not done accurately at scale by the vulnerability management ecosystem.
> 
> Accurate root cause mapping is valuable because it directly illuminates where investments, policy, and practices can address the root causes responsible for vulnerabilities so that they can be eliminated. This applies to both industry and government decision makers. Additionally, it enables:
> 1. Driving the removal of classes of vulnerabilities: Root cause mapping encourages a valuable feedback loop into a vendor’s SDLC or architecture design planning
> 2. Saving money: the more weaknesses avoided in your product development, the less vulnerabilities to manage after deployment
> 3. Trend analysis (e.g., how big of a problem is memory safety compared to other problems like injection)
> 4. Further insight to potential “exploitability” based on root cause (e.g., command injection vulnerabilities tend to see increased adversary attention, be targeted by certain actors)
> 5. Organizations demonstrating transparency to customers how they are targeting and tackling problems in their products


The [MITRE CWE (Common Weakness Enumeration) specification](https://cwe.mitre.org/) is a comprehensive list of software and hardware security vulnerabilities. It categorizes weaknesses to help identify and mitigate security flaws. The specification covers various types of weaknesses, from coding errors to design flaws. 

While it provides a clear framework, its complexity lies in the extensive classification system, the technical nature of vulnerabilities, and its depth, requiring detailed understanding of security, coding practices, and risk management to effectively use it.

There are ~~1000 CWEs, and the PDF version is almost 3000 pages.



### Narrative 

#### Pre-Narrative (how things are now)
People struggle with the amount of information in [MITRE CWE](https://cwe.mitre.org/), and may not have the understanding of security required to assign CWEs.

Today, assigning CWEs is not done accurately at scale by the vulnerability management ecosystem. It is generally done manually.

#### Post-Narrative (how we want things to be in the future - aspirational)
Given a Vulnerability Description and related text (e.g. from bug or vulnerability references), the CWE(s) are automatically assigned with
1. the root cause and other weakness highlighted
2. the rationale for their choice including other CVE examples from CWE Observed Examples or CWE Top25 Mappings with similar weakness(es) and CWE assignment(s).
3. the chain of CWEs from root cause to follow on weaknesses




## Create a CWE Expert: Interactively Assign CWEs

### Solution 

> [!TIP]
> 💁 A CWE-Expert can be built for free in a browser in less than 1 minute using the instruction and CWE Corpus files provided here.

> You can ask your CWE-Expert
> - any questions about CWEs
> - to assign CWEs to vulnerability descriptions
> A CWE-Expert can be built for free in a browser in less than 1 minute using the CWE Corpus files and prompts 
> 
> See https://github.com/CyberSecAI/CWE-Expert
>
> **Demo**
> - [Youtube video](https://www.youtube.com/watch?v=DAWJjYCpudE) showing general CWE questions, and CWE assignment for several CVEs
>     - [![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/DAWJjYCpudE/0.jpg)](https://www.youtube.com/watch?v=DAWJjYCpudE)
> - [Some nuanced CWE assignments](./prompts/CVE_assignments.md)



### Background 
As any user, I want to assign CWEs with the assistance of an expert on MITRE CWE specification and security 
* to be able to get answers to my questions
* to get recommendations
* to be able to provide input and feedback to the expert

### Narrative 

#### Pre-Narrative (how things are now)

Users need to have a deep understanding of the MITRE CWE specification, or need to spend time searching for the appropriate CWE information.

#### Post-Narrative (how we want things to be in the future - aspirational)

Users can chat with a CWE expert that can provide CWE recommendations for vulnerability descriptions, and answer general questions of CWEs.


# User Stories

User Stories are shorter, more point specific requirements than User Scenarios.

## Bulk Check CWEs
As any user, I want to check CWEs for CVE Descriptions in bulk automatically, so I can then assign the correct CWEs.

> [!TIP]
> A Solution Proof Of Concept was implemented that asked a Consensus of 3 state of the art LLMs if the a population of CWEs assigned by CISA Vulnrichment was correct or not. 
> 

## CVE Description Duplicates
As any user, I want to know what CVE Descriptions are exact or close (fuzzy) Duplicates

> [!TIP]
> See https://github.com/CyberSecAI/cve_dedup

The numbers
- 237863: CVEs at the time of analysis
- 157158: Unique CVE Descriptions
- 80705: Duplicate CVE Descriptions (exact or close (fuzzy) duplicates)
- 21429: Number of duplicate groups
- 669: Largest duplicate group per [plot](https://github.com/CyberSecAI/cve_dedup/blob/main/_top100_sizes_horizontal_plot.png) i.e. 669 CVE Descriptions are (almost) same.
- 2: The most common number of duplicates per [plot](https://github.com/CyberSecAI/cve_dedup/blob/main/_top50_plot.png)

# Repo Overview
```mermaid
classDiagram
    class VulnerabilityDescriptionQualityChecker {
        Analysis of KeyPhrases from published CVEs
        This can be used to assess the quality of CVE Descriptions
        based on how many of the 8 vulnerability keyphrase types they have.
    }
    
    class cve_info {
        Vulnerability KeyPhrases extracted from published CVEs
    }
    
    class keyphrase_analyzer {
        This analyzes and refines the KeyPhrases extracted by the KeyPhraseExtractionModel
         to improve the dataset so it can be used to finetune a KeyPhraseExtractionModel with more and better data.
    }
    
    class KeyPhraseExtractionModel {
        FineTuned LLM for extracting KeyPhrases from published CVEs
        
    }
    
    class cve_source_of_truth {
        TBC: Single repo as source of truth
        Collates info from NVD, CVEv5project
        and other sources
    }
    
    class nvd_cve_data {
        CVE data downloaded from
        NVD to a CSV file
    }
    
    class cve_dedup {
        An analysis of what CVEs are exact / fuzzy duplicates
    }
    
    class CWE_Expert {
        The corpus files and instructions to build an interative CWE Expert.
    }
    
    class CyberSecAI_github_io {
        Source for a guide to using LLMs for Cybersecurity
    }

    VulnerabilityDescriptionQualityChecker --> cve_info
    keyphrase_analyzer --> cve_info
    cve_source_of_truth --> nvd_cve_data
    cve_info <-- KeyPhraseExtractionModel

````
