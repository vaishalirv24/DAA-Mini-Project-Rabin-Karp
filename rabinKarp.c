#include <stdio.h>
#include <string.h>

#define d 256

void rabinKarp(char text[], char pattern[], int q)
{
    int m = strlen(pattern);
    int n = strlen(text);
    int i, j;
    int p = 0; // hash value for pattern
    int t = 0; // hash value for text
    int h = 1;

    // Calculate h = pow(d, m-1) % q
    for(i = 0; i < m - 1; i++)
        h = (h * d) % q;

    // Calculate initial hash values
    for(i = 0; i < m; i++)
    {
        p = (d * p + pattern[i]) % q;
        t = (d * t + text[i]) % q;
    }

    // Slide pattern over text
    for(i = 0; i <= n - m; i++)
    {
        // Hash matched
        if(p == t)
        {
            for(j = 0; j < m; j++)
            {
                if(text[i + j] != pattern[j])
                    break;
            }

            if(j == m)
            {
                printf("Threat Detected: %s\n", pattern);
                printf("Position: %d\n\n", i);
            }
        }

        // Calculate next window hash
        if(i < n - m)
        {
            t = (d * (t - text[i] * h) + text[i + m]) % q;

            if(t < 0)
                t = t + q;
        }
    }
}

int main()
{
    char text[500];

    char threats[][20] = {
        "malware",
        "trojan",
        "virus",
        "phishing",
        "ransomware"
    };

    int n = 5;

    printf("Enter log/message:\n");
    fgets(text, sizeof(text), stdin);

    printf("\nScanning for threats...\n\n");

    for(int i = 0; i < n; i++)
    {
        rabinKarp(text, threats[i], 101);
    }

    return 0;
}