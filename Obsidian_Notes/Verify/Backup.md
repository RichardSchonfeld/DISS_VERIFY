
% UCL Thesis LaTeX Template
%  (c) Nicole Mantl, 2022

\documentclass[12pt, english]{report}
\usepackage[utf8]{inputenc}
\usepackage[a4paper, lmargin=4cm, rmargin=2cm, tmargin=1in, bmargin=1in]{geometry}
\usepackage{graphicx}
\usepackage{mathptmx}
\usepackage{amsmath}
\usepackage{gensymb}
\usepackage{indentfirst}
\usepackage{appendix}
\usepackage{helvet}
\usepackage{pifont}
\usepackage{wrapfig}
\usepackage{dirtytalk}
\usepackage{longtable}
\usepackage{fontenc, anyfontsize}
\usepackage{ragged2e}
\usepackage{titletoc}
\usepackage{tocloft}

\linespread{1.40}
\setlength{\parindent}{.5cm}

\usepackage{caption}
\captionsetup{font=footnotesize}

\usepackage{subcaption}
\usepackage{array,booktabs,multirow}
\newcolumntype{L}{>{\centering\arraybackslash}m{2.1cm}}
\usepackage{pdflscape}

\usepackage{titlesec}
\titleformat{\chapter}[display]{\normalfont\huge\centering}   {\textbf{\textasteriskcentered{}\ \chaptertitlename\ \thechapter\ \textasteriskcentered{}}}{15pt}{\fontsize{22pt}{20pt}\selectfont}
\titlespacing{\chapter}{0pt}{-32pt}{2cm}
\titleformat{\section}{\scshape\LARGE}{\thesection}{0.3em}{}
\titlespacing{\section}{0pt}{32pt}{.5cm}
\titleformat{\subsection}{\normalfont\Large}{\themysubsection}{0.5em}{}
\titlespacing{\subsection}{0pt}{32pt}{.4cm}
\titleformat{\subsubsection}{\fontsize{16pt}{14pt}\selectfont}{\themysubsubsection}{0.5em}{}
\titlespacing{\subsubsection}{0pt}{32pt}{.3cm}
\titleformat{\paragraph}[hang]{\fontsize{14.5pt}{12pt}\selectfont}{\theparagraph}{0.5em}{}
\titlespacing{\paragraph}{0pt}{32pt}{.2cm}
\titleformat{\subparagraph}[drop]{\itshape\fontsize{13pt}{12pt}\selectfont}{\thesubparagraph}{0.5em}{}
\titlespacing*{\subparagraph}{3cm}{20pt}{.3cm}


\setcounter{secnumdepth}{5}

\usepackage{natbib}
\bibliographystyle{plain}
\renewcommand{\bibname}{\textbf{\huge{References}}}
\setcitestyle{aysep={}} 

\usepackage{tikz,pgfplots}
\usepackage{pgfplotstable}
\pgfplotsset{compat=1.15}
\usetikzlibrary{shapes.geometric, arrows}
\tikzstyle{startstop} = [rectangle, rounded corners, minimum width=3cm, minimum height=1cm, text centered, draw=black]
\tikzstyle{io} = [trapezium, trapezium left angle=70, trapezium right angle=110, minimum width=4cm, minimum height=1cm, text centered, text width=3.5cm,  trapezium stretches=true, draw=black]
\tikzstyle{process} = [rectangle, minimum width=4cm, minimum height=1cm, text centered, text width=4cm, draw=black]
\tikzstyle{decision} = [diamond, aspect=3, minimum width=3cm, text centered, text width=3.0cm, draw=black]
\tikzstyle{arrow} = [thick, ->, >=stealth]
\usetikzlibrary{positioning, arrows}

\usepackage{abstract}
\renewcommand{\abstractnamefont}{}
\usepackage{etoolbox}
\patchcmd{\abstract}{\null\vfill}{}{}{}

\setcounter{tocdepth}{5}

\renewcommand{\cftchapfont}{\bfseries}
\renewcommand{\cftchappagefont}{\bfseries}
\renewcommand{\cftchappresnum}{Chapter }
\renewcommand{\cftchapnumwidth}{6em}
\renewcommand{\cftsecnumwidth}{1.5em}
\renewcommand{\cftsubsecnumwidth}{2.2em}
\renewcommand{\cftsubsubsecnumwidth}{2.9em}
\renewcommand{\cftparanumwidth}{1.5em}
\renewcommand{\cftsubparanumwidth}{1.5em}
\renewcommand{\cftsubsecindent}{3em}
\renewcommand{\cftsubsubsecindent}{5.2em}
\renewcommand{\cftparaindent}{8.1em}
\renewcommand{\cftsubparaindent}{9.7em}
\renewcommand{\cftfignumwidth}{3em}
\renewcommand{\cfttabnumwidth}{3em}

\cftsetpnumwidth{0cm}
\cftsetrmarg{0.4cm}

\makeatletter
\newcommand*\updatechaptername{%
	\addtocontents{toc}{\protect\renewcommand*\protect\cftchappresnum{\@chapapp\ }}
}
\makeatother

\cftpagenumbersoff{chapter} 
\usepackage{epigraph}

\usepackage{chngcntr}
\counterwithout{equation}{chapter}
\renewcommand{\thechapter}{\Roman{chapter}}
\renewcommand{\thesection}{\arabic{section})}
\renewcommand{\thesubsection}{\themysubsection}
\renewcommand{\thesubsubsection}{\themysubsubsection}
\renewcommand{\theparagraph}{\alph{paragraph}.}
\renewcommand{\thesubparagraph}{--}
\renewcommand{\thefigure}{\Roman{chapter}.\arabic{figure}}
\renewcommand{\thetable}{\Roman{chapter}.\arabic{table}}

\newcommand{\themysubsection}{\arabic{section}.\arabic{subsection}}
\newcommand{\themysubsubsection}{\arabic{section}.\arabic{subsection}.\arabic{subsubsection}}

\usepackage{url}

%% Define a new 'leo' style for the package that will use a smaller font.
\makeatletter
\def\url@leostyle{%
  \@ifundefined{selectfont}{\def\UrlFont{\sf}}{\def\UrlFont{\footnotesize\sffamily}}}
\makeatother
%% Now actually use the newly defined style.
\urlstyle{leo}

\newcommand\mysection[2]{\section[#1]{#1\hrulefill}}

\newcommand\Section[2]{\section[#1: {#2}]{#1\hrulefill\\[-2ex]\normalsize\itshape#2}}

\newcommand\Chapter[2]{\chapter[\textsl{#1: {#2}}]{\textsl{#1}\\[1ex]\Large{#2}}}

\begin{document}
%TC:ignore
\begin{titlepage}

   \begin{center}
       \vspace*{3cm}
       {TITLE}
 
       \vspace{4cm}
 
       {Your name}\\
       
       \vspace*{10cm}
      
       
      UCL\\
      
      Ph.D. [Your degree]\\
      
      202x
      
 
   \end{center}
\end{titlepage}

\setcounter{page}{2}
\noindent
\LARGE{Declaration}\\

\vspace{.5cm}

\normalsize{I, [your name] confirm that the work presented in this thesis is my own. Where information has been derived from other sources, I confirm that this has been indicated in the thesis.}\\

\vspace{1cm}

Signed \hspace{2cm}    ...................................\\

\vspace{1cm}

Date   \hspace{2.4cm}    ...................................\\

\clearpage

\clearpage

\chapter*{\huge{\textbf{Abstract}}}
%\input{}

\chapter*{\huge{\textbf{Project theme, objectives, and introduction}}}

The recent rise of Generative AI and its increasing ability to create images, documents and other forms of collected data have stirred and increasing concern of credential falsification. Fraud is both harder to detect, while simultaneously forged documents are getting easier (and cheaper) to create --ref-- .
\par
With globalization enabling a larger pool of opportunity, at the cost of higher competition, many people find themselves boasting their accomplishments beyond their genuine capacity, or outright lying about their credentials to give themselves a more competitive position on a highly-saturated job market. A survey of 2,100 Americans revealed $64.2\%$ admitted of lying on their resume, with younger people more likely to lie. Commonly including salary, skills and work experience and education. $54\%$ of those who lied about their education claiming they had degrees while not being a graduate of any college.

\begin{table}[htbp]
    \centering
        \begin{tabular}{|l|c|}
        \hline
        \textbf{Metric} & \textbf{Percentage/Value} \\ \hline
        People who lied on resumes (overall) & 64.2\% \\ \hline
        Men who lied on resumes & 65.6\% \\ \hline
        Women who lied on resumes & 63.3\% \\ \hline
        People aged 18-25 who lied & 80.4\% \\ \hline
        People aged 65+ who lied & 46.9\% \\ \hline
        Lied about salary & 32.8\% \\ \hline
        Lied about skills & 30.8\% \\ \hline
        Lied about work experience & 30.5\% \\ \hline
        Lied about having a college degree & 29.6\% \\ \hline
        People who used fake job reference services & 18.5\% \\ \hline
        Average cost of fake reference & \$128.60 \\ \hline
        People considering AI to embellish resumes & 73.4\% \\ \hline
        \end{tabular}
    \caption{Key Findings from StandOut CV Study on Resume Lies}
\end{table}

\textbf{Applicant reasoning} \par
The provided reasoning for lying was primarily applicant's belief they wouldn't be caught and that they would fit the job requirements for which job listings required experience/education above the applicant's current level. 
\paragraph{}
\textbf{Employed perspective} \par
According to a study \cite{intelligent2023degree}, half of hiring managers do not verify educational credentials. 

\begin{table}[htbp]
    \centering
        \begin{tabular}{|l|c|}
        \hline
        \textbf{Metric} & \textbf{Percentage/Value} \\ \hline
        Hiring managers who verify educational credentials & 53\% \\ \hline
        Hiring managers who sometimes verify credentials & 24\% \\ \hline
        Hiring managers who never verify credentials & 23\% \\ \hline
        Managers who caught candidates lying about education & 9 in 10 \\ \hline
        Employers who value experience over education & 36\% \\ \hline
        Companies that don’t verify due to time/cost constraints & 23\% \\ \hline
        \end{tabular}
    \caption{Key Findings on Educational Verification from Intelligent.com Study}
\end{table}

When asked the typical responses for lack of verification were related to the time-exhaustive process of the current standard approach, typically employers reach out to schools directly, request transcripts from candidates, or hire background check services \cite{businessnews2023verification}. \par
The time and/or monetary cost associated with background checks and connecting with different schools or entities (particularly if a candidate has multiple degrees and certifications) is suboptimal. Additionally, as discussed earlier in this section, trusting candidates to produce 'valid' transcripts may not be the ideal either.
\par
Faking credentials harms the reputation and credibility of institutions while simultaneously diminishing the value of legitimate credentials, creating an unfair competition on the job market.
\paragraph{}
This project offers an alternative, more transparent, verifiable, and cost-effective credential validation system. \par




\chapter*{\huge{\textbf{Project architecture}}}
This project is built as a partially-decentralized, privacy-friendly hybrid authentication platform that offers a flexible model of 




While there are other decentralized services that offer credential verification like \cite{blockcerts2024}, this Dapp takes a fundementally different approach to claim submission and verification. \par
Typically, as in \cite{blockcerts2024}, the authority already possesses all the information required, is subscribed to the service, and the individual merely requests verification. This is undesirable for several reasons, namely in ...



\begin{itemize}
    \item \textbf{Limited User Control}: Users have little autonomy over their credential management, as the authority holds all the necessary information and initiates the process.
    \item \textbf{Flexibility}: Using IPFS, this Dapp allows for the integration of arbitrary data, enabling the storage of various credential types and formats. In contrast, traditional services like Blockcerts may limit the kinds of data that can be stored, restricting the system's adaptability to different credentialing needs.
    \item \textbf{Privacy Concerns}: With institutions holding centralized control of sensitive data, there is a risk of mishandling or unauthorized access to private information.
\end{itemize}




\chapter*{\huge{\textbf{Web3 and its adoption}}}
Web3 is 
There are several reasons why Web3 hasn't become 'mainstream' yet. 

\chapter*{\huge{\textbf{Ethereum and the Blockchain}}}

Blockchain technology originated with the introduction of Bitcoin in 2008, through Satoshi Nakamoto's whitepaper \cite{bitcoin-whitepaper} describing a peer-to-peer, decentralized ledger that can serve as an electronic cash system. This system introduced a large-scale, completely sovereign network with no central authority - a self-governing electronic cash system.\par
In current-day banking, where commercial and central banks control the issuance, distribution, and regulation of fiat currency, interest rates and monetary policy - decisions on actions are made by a central governing body, such as the central bank's board of governors.
In other words - one particular institution retains control, and with that the upkeep and enforcement of its system and policy. All participants in that system are obligated to follow a set of rules, and are not allowed to participate if they refuse. I.e. a person cannot withdraw a $\$1000$ from their debit account if their balance is $\$100$, and so on.\par
\par
In order for a seemingly govern-less system with no single authority that enforces policies, or makes decisions on improvements to function appropriately, there needs to be an effective mechanism for achieving consensus. This is where the blokchain comes in.\par
The blockchain is a shared, immutable ledger that facilitates the process of recording transactions and tracking assets in a business network \cite{ibm_blockchain}. Every client participating on a blockchain-base network holds their own, invidual copy of the chain's history, ensuring transparency and security. All copies are synchronized and consistent, and the mechanisms behind each blockchain-based service such as Bitcoin and Ethereum ensure the ...


\textbf{Ethereum}
Ethereum was founded by Vitalik Buterin, announced in 2014 as an 'upgrade' to Bitcoin and its scripting language. \cite{buterin2013ethereum}
The project's intention was to create a "world computer" that could execute code in a decentralized manner. The system was built with turing-ready virtual machines that could arbitrary computation. This allowed for developers to write self-executing smart-contracts, "typically used to automate the execution of an agreement so that all participants can be immediately certain of the outcome, without any intermediary’s involvement or time loss. They can also automate a workflow, triggering the next action when predetermined conditions are met." \cite{ibm_smart_contracts}. These virtual contracts bring numerous benefits, namely the removal of a need for intermediary entities (i.e. an escrow for real estate transaction) reducing transaction cost while retaining obligations to all parties involved for the contract to become valid.
\paragraph{}
This project levarages smart contracts to provide a claiming-authority relationship with a rule-set both parties must follow to submit a claim, securely transmit any information, and obtain a digital signature by the authority for the claim. In this project, this means the claimant attests they've attended and graduated a university course, and the university verifies them digitally.\par
Powered by the blockchain, this ensures the signature remains as a permanent record ...




\chapter*{\huge{\textbf{Shamirs Secret Sharing Scheme (SSSS)}}}
While there are other decentralized services that offer credential verification like \cite{blockcerts2024}, this Dapp takes a fundementally different approach to claim submission and verification. \par
Typically, as in \cite{blockcerts2024}, the authority already possesses all the information required, is subscribed to the service, and the individual merely requests verification. This is undesirable for several reasons:
\begin{itemize}
    \item \textbf{Limited User Control}: Users have little autonomy over their credential management, as the authority holds all the necessary information and initiates the process.
    \item \textbf{Flexibility}: Using IPFS, this Dapp allows for the integration of arbitrary data, enabling the storage of various credential types and formats. In contrast, traditional services like Blockcerts may limit the kinds of data that can be stored, restricting the system's adaptability to different credentialing needs.
    \item \textbf{Privacy Concerns}: With institutions holding centralized control of sensitive data, there is a risk of mishandling or unauthorized access to private information.
\end{itemize}

In this prject, Shamir's Secret Sharing Scheme (SSSS) \cite{shamir1979} is utilized to securely manage the encryption and decryption keys for credential data stored on IPFS. 

For a simple comparison, imagine a function $f$ that denotes a line --- 

$f(x) = S + a_1x + a_2x^2 + \dots + a_{k-1}x^{k-1} \mod p$
$\text{Share for participant } i = (x_i, f(x_i))$
$f(0) = \sum_{i=1}^{k} y_i \prod_{1 \leq j \leq k, j \neq i} \frac{x_j}{x_j - x_i} \mod p$

In more simple terms, imagine a function $f(x) = 10 - 2x$ which ... if you have only 1 point on the graph you aren't able to guess the $y$ coordinate associated with the full secret, however once you add in a secondary point you are able to reconstruct the intended function and find the intended $y$-value.

... below describes this:

\begin{figure}[h]
    \centering
    \begin{tikzpicture}[scale=1.5]
        % Draw axes
        \draw[->] (-1,0) -- (6,0) node[right] {$x$}; % X-axis
        \draw[->] (0,-1) -- (0,11) node[above] {$y$}; % Y-axis
        
        % Mark and label the points (2,6) and (3,4)
        \filldraw[blue] (2,6) circle (2pt) node[above right] {$(2, 6)$}; % Marked blue
        \filldraw[red] (3,4) circle (2pt) node[above right] {$(3, 4)$}; % Marked red
        
        % The actual blue line between points (2,6) and (3,4)
        \draw[thick, blue] (0,10) -- (6,-2); % The actual blue line crosses both points

        % Red lines (equidistant slopes) passing through (3,4) and with length 2/3 of the blue line
        \foreach \i in {-3,-2.5,-2,-1.5,1.5,2,2.5,3} {
            \draw[thick, red] (3, 4) -- ({3 + 0.67*(3-0)}, {4 + \i * 0.67*(10-4)});
        }

        % Label important points
        \node at (-0.5, 10) {$(0, 10)$};
        \node at (2,-0.5) {2};
        \node at (3,-0.5) {3};

        % Add a legend
        \draw[thick, blue] (0.5, 9.5) -- (1.5, 9.5);
        \node at (3.5, 9.5) {Line accurately crossing between two points (reconstructed secret)};
        
        \draw[thick, red] (0.5, 8.5) -- (1.5, 8.5);
        \node at (3.5, 8.5) {Equally distributed shorter lines with one point (ambiguous secret)};
    \end{tikzpicture}
    \caption{Visualization of uncertainty with one point and certainty with two points.}
    \label{fig:shamir_graph}
\end{figure}

\begin{figure}[h]
    \centering
    \begin{tikzpicture}[scale=1.5]
        % Draw axes
        \draw[->] (-1,0) -- (6,0) node[right] {$x$}; % X-axis
        \draw[->] (0,-1) -- (0,11) node[above] {$y$}; % Y-axis
        
        % Mark and label the points (2,6) and (3,4)
        \filldraw[blue] (2,6) circle (2pt) node[above right] {$(2, 6)$}; % Marked blue
        \filldraw[red] (3,4) circle (2pt) node[above right] {$(3, 4)$}; % Marked red
        
        % The actual blue line between points (2,6) and (3,4)
        \draw[thick, blue] (0,10) -- (6,-2); % The actual blue line crosses both points
        
        % Red lines (equidistant slopes) passing through (3,4) and shortened
        \foreach \i in {-3,-2.5,-2,-1.5,1.5,2,2.5,3} {
            \draw[thick, red] (3, 4) -- ({3 + 0.5}, {4 + \i * 0.5}); % Shorter red lines, don't cross the full graph
        }
        
        % Label important points
        \node at (-0.5, 10) {$(0, 10)$};
        \node at (2,-0.5) {2};
        \node at (3,-0.5) {3};

        % Add a legend
        \draw[thick, blue] (0.5, 9.5) -- (1.5, 9.5);
        \node at (3.5, 9.5) {Line accurately crossing between two points (reconstructed secret)};
        
        \draw[thick, red] (0.5, 8.5) -- (1.5, 8.5);
        \node at (3.5, 8.5) {Shorter lines with only one point (ambiguous secret)};
    \end{tikzpicture}
    \caption{Visualization of uncertainty with one point and certainty with two points.}
    \label{fig:shamir_graph}
\end{figure}




\begin{figure}[h]
    \centering
    \begin{tikzpicture}[scale=1.5]
        % Draw axes
        \draw[->] (-1,0) -- (6,0) node[right] {$x$}; % X-axis
        \draw[->] (0,-1) -- (0,11) node[above] {$y$}; % Y-axis
        
        % Plot the function f(x) = 10 - 2x
        \draw[domain=-0.5:5.5, smooth, variable=\x, blue, thick] plot ({\x},{10-2*\x}) node[right] {$f(x) = 10 - 2x$};
        
        % Mark and label the points (2,6) and (3,4)
        \filldraw[red] (2,6) circle (2pt) node[above right] {$(2, 6)$};
        \filldraw[red] (3,4) circle (2pt) node[above right] {$(3, 4)$};
        
        % Dashed line to y-axis from the point (2,6)
        \draw[dashed] (2,6) -- (0,10);
        
        % Extend line through the points
        \draw[dashed] (2,6) -- (3,4);
        
        % Label important points
        \node at (-0.5, 10) {$(0, 10)$};
        \node at (2,-0.5) {2};
        \node at (3,-0.5) {3};
    \end{tikzpicture}
    \caption{Graph showing points $(2,6)$ and $(3,4)$ with the line $f(x) = 10 - 2x$.}
    \label{fig:shamir_graph}
\end{figure}



%\input{}

\clearpage
\updatechaptername
\chapter*{\huge{\textbf{Acknowledgements}}}
%\input{}


\setlength{\cftbeforetoctitleskip}{-22pt}
\setlength{\cftaftertoctitleskip}{-22pt}
\renewcommand{\contentsname}{\huge\textbf{Table of Contents}}
\renewcommand{\cfttoctitlefont}{\chapter*}

\tableofcontents

\clearpage

\setlength{\cftbeforeloftitleskip}{-22pt}
\renewcommand{\cftloftitlefont}{\hfill\huge\bfseries}
\renewcommand{\cftafterloftitle}{\hfill}
\listoffigures

\clearpage

\setlength{\cftbeforelottitleskip}{-22pt}
\renewcommand{\cftlottitlefont}{\hfill\huge\bfseries}
\renewcommand{\cftafterlottitle}{\hfill}
\listoftables


%TC:endignore
\cleardoublepage

\chapter{\textsl{Introduction}}

%\input{}

\chapter{\textsl{Literature/Systematic Review}}

%\input{}

\chapter{\textsl{Section 1: Digital identity}}
A plausible system for affirming user's claims to different achievements must ensure all enlisted entities are who they claim to be. This paper quantifies 

\chapter{\textsl{Empirical chapter}}

%\input{}


\chapter{\textsl{Discussion}}

%\input{}

\chapter{\textsl{Conclusion}}

%\input{}

%%TC:ignore
\newpage

\addtocontents{toc}{\cftpagenumberson{chapter}}
\addcontentsline{toc}{chapter}{\textbf{References}}
\bibliography{references}

\clearpage

\appendix
\updatechaptername
\titleformat{\chapter}[display]{\normalfont\LARGE}   {\textbf{\chaptertitlename\ \thechapter:}}{0cm}{\large} \titlespacing{\chapter}{0cm}{-40pt}{.7cm}

\renewcommand{\thefigure}{\Alph{chapter}.\arabic{figure}}
\renewcommand{\thetable}{\Alph{chapter}.\arabic{table}}

\updatechaptername
\chapter{\textsl{Appendix}}
%\input{}

\end{document}