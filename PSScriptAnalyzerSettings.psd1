@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSAvoidUsingInvokeExpression',
        'PSUseApprovedVerbs',
        'PSAvoidUsingPositionalParameters',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidUsingWMICmdlet',
        'PSAvoidUsingCmdletAliases',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSAvoidGlobalVars',
        'PSAvoidUsingUsernameAndPasswordParams',
        'PSAvoidUsingPlainTextForPassword',
        'PSUseBOMForUnicodeEncodedFile',
        'PSUseSingularNouns',
        'PSAvoidUsingEmptyCatchBlock',
        'PSAvoidAssignmentToAutomaticVariable',
        'PSReviewUnusedParameter',
        'PSUseOutputTypeCorrectly',
        'PSUseLiteralInitializerForHashtable',
        'PSPossibleIncorrectComparisonWithNull'
    )
}
