
/**
 Analyzes the tone of a piece of text. The message is analyzed for several tones - social, emotional, and language.
 For each tone, various traits are derived. For example, conscientiousness, agreeableness, and openness.
 **/
var analyzeTone = function(text, options) {
    return endpoint.post({
        body: {
            "text" : text
        },
        params: options
    });
};

// Public API
endpoint.analyzeTone = analyzeTone;