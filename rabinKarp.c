#include <stdio.h>
#include <string.h>

#define d 256

int rabinKarp(char text[], char pattern[], int q)
{
    int m = strlen(pattern);
    int n = strlen(text);
    int i, j;
    int p = 0;
    int t = 0;
    int h = 1;
    int detected = 0;

    for(i = 0; i < m - 1; i++)
        h = (h * d) % q;

    for(i = 0; i < m; i++)
    {
        p = (d * p + pattern[i]) % q;
        t = (d * t + text[i]) % q;
    }

    for(i = 0; i <= n - m; i++)
    {
        if(p == t)
        {
            for(j = 0; j < m; j++)
            {
                if(text[i + j] != pattern[j])
                    break;
            }

            if(j == m)
            {
                detected = 1;

                printf("Threat Detected: %s\n", pattern);
                printf("Position: %d\n\n", i);
            }
        }

        if(i < n - m)
        {
            t = (d * (t - text[i] * h) + text[i + m]) % q;

            if(t < 0)
                t = t + q;
        }
    }

    return detected;
}

int main()
{
    char text[500];

    char threats[][20] =
    {
        "malware",
        "trojan",
        "virus",
        "phishing",
        "ransomware"
    };

    int n = 5;
    int found = 0;

    printf("Enter log/message:\n");
    fgets(text, sizeof(text), stdin);

    printf("\nScanning for threats...\n\n");

    for(int i = 0; i < n; i++)
    {
        if(rabinKarp(text, threats[i], 101))
        {
            found = 1;
        }
    }

    if(found == 0)
    {
        printf("No threats detected.\n");
    }

    return 0;
}
