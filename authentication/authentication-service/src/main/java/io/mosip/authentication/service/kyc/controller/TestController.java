package io.mosip.authentication.service.kyc.controller;

import io.mosip.authentication.common.service.builder.AuthTransactionBuilder;
import io.mosip.authentication.common.service.helper.AuditHelper;
import io.mosip.authentication.common.service.helper.AuthTransactionHelper;
import io.mosip.authentication.common.service.util.AuthTypeUtil;
import io.mosip.authentication.common.service.util.IdaRequestResponsConsumerUtil;
import io.mosip.authentication.common.service.validator.AuthRequestValidator;
import io.mosip.authentication.common.service.websub.impl.OndemandTemplateEventPublisher;
import io.mosip.authentication.core.constant.AuditEvents;
import io.mosip.authentication.core.constant.IdAuthCommonConstants;
import io.mosip.authentication.core.constant.IdAuthenticationErrorConstants;
import io.mosip.authentication.core.dto.ObjectWithMetadata;
import io.mosip.authentication.core.exception.IDDataValidationException;
import io.mosip.authentication.core.exception.IdAuthenticationAppException;
import io.mosip.authentication.core.exception.IdAuthenticationBusinessException;
import io.mosip.authentication.core.exception.IdAuthenticationDaoException;
import io.mosip.authentication.core.indauth.dto.AuthResponseDTO;
import io.mosip.authentication.core.indauth.dto.KycAuthRequestDTO;
import io.mosip.authentication.core.indauth.dto.KycAuthResponseDTO;
import io.mosip.authentication.core.logger.IdaLogger;
import io.mosip.authentication.core.partner.dto.PartnerDTO;
import io.mosip.authentication.core.spi.indauth.facade.KycFacade;
import io.mosip.authentication.core.spi.partner.service.PartnerService;
import io.mosip.authentication.core.util.DataValidationUtil;
import io.mosip.authentication.core.util.IdTypeUtil;
import io.mosip.authentication.service.kyc.validator.KycAuthRequestValidator;
import io.mosip.authentication.service.kyc.validator.KycExchangeRequestValidator;
import io.mosip.kernel.core.logger.spi.Logger;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.Errors;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import springfox.documentation.annotations.ApiIgnore;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@RestController
@Tag(name = "test-auth-controller", description = "Test Controller")
public class TestController {

    /** The mosipLogger. */
    private Logger mosipLogger = IdaLogger.getLogger(KycAuthController.class);

    /** The KycAuthRequestValidator */
    @Autowired
    private KycAuthRequestValidator kycReqValidator;

    /** The auth request validator. */
    @Autowired
    private AuthRequestValidator authRequestValidator;

    /** The auth facade. */
    @Autowired
    private KycFacade kycFacade;

    @Autowired
    private AuditHelper auditHelper;

    @Autowired
    private IdTypeUtil idTypeUtil;

    @Autowired
    private AuthTransactionHelper authTransactionHelper;

    @Autowired
    private PartnerService partnerService;

    /** The KycExchangeRequestValidator */
    @Autowired
    private KycExchangeRequestValidator kycExchangeValidator;

    @Autowired
    private OndemandTemplateEventPublisher ondemandTemplateEventPublisher;

    /**
     *
     * @param binder the binder
     */
    @InitBinder("kycAuthRequestDTO")
    private void initKycAuthRequestBinder(WebDataBinder binder) {
        binder.setValidator(authRequestValidator);
    }

    /**
     *
     * @param binder the binder
     */
    @InitBinder("ekycAuthRequestDTO")
    private void initEKycBinder(WebDataBinder binder) {
        binder.setValidator(kycReqValidator);
    }

    /**
     *
     * @param binder the binder
     */
    @InitBinder("kycExchangeRequestDTO")
    private void initKycExchangeBinder(WebDataBinder binder) {
        binder.setValidator(kycExchangeValidator);
    }




    @PostMapping(path = "/ky-test/Test/{IdP-LK}/{Auth-Partner-ID}/{OIDC-Client-Id}")
    @Operation(summary = "Kyc Auth Request", description = "Kyc Auth Request", tags = { "kyc-auth-controller" })
    @SecurityRequirement(name = "Authorization")
    @Parameter(in = ParameterIn.HEADER, name = "signature")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Request authenticated successfully",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = IdAuthenticationAppException.class)))),
            @ApiResponse(responseCode = "201", description = "Created" ,content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized" ,content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden" ,content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found" ,content = @Content(schema = @Schema(hidden = true)))})
    public KycAuthResponseDTO processKycAuthTest(@RequestBody KycAuthRequestDTO authRequestDTO,
                                                 @ApiIgnore Errors errors, @PathVariable("IdP-LK") String mispLK, @PathVariable("Auth-Partner-ID") String partnerId,
                                                 @PathVariable("OIDC-Client-Id") String oidcClientId, HttpServletRequest request)
            throws IdAuthenticationBusinessException, IdAuthenticationAppException, IdAuthenticationDaoException {
        mosipLogger.info("Checking instance type of request: " + request.getClass().getName());

        if(true) {
            ObjectWithMetadata requestWrapperWithMetadata = (ObjectWithMetadata) request;

            boolean isAuth = true;
            Optional<PartnerDTO> partner = partnerService.getPartner(partnerId, authRequestDTO.getMetadata());
            AuthTransactionBuilder authTxnBuilder = authTransactionHelper
                    .createAndSetAuthTxnBuilderMetadataToRequest(authRequestDTO, !isAuth, partner);

            try {
                String idType = Objects.nonNull(authRequestDTO.getIndividualIdType()) ? authRequestDTO.getIndividualIdType()
                        : idTypeUtil.getIdType(authRequestDTO.getIndividualId()).getType();
                authRequestDTO.setIndividualIdType(idType);
                authRequestValidator.validateIdvId(authRequestDTO.getIndividualId(), idType, errors);
                if(AuthTypeUtil.isBio(authRequestDTO)) {
                    kycReqValidator.validateDeviceDetails(authRequestDTO, errors);
                }
                DataValidationUtil.validate(errors);
                boolean externalAuthRequest = true;
                AuthResponseDTO authResponseDTO = kycFacade.authenticateIndividual(authRequestDTO, externalAuthRequest, partnerId,
                        oidcClientId, requestWrapperWithMetadata, IdAuthCommonConstants.KYC_AUTH_CONSUME_VID_DEFAULT);
                KycAuthResponseDTO kycAuthResponseDTO = new KycAuthResponseDTO();
                Map<String, Object> metadata = requestWrapperWithMetadata.getMetadata();
                if (authResponseDTO != null &&
                        metadata != null &&
                        metadata.get(IdAuthCommonConstants.IDENTITY_DATA) != null &&
                        metadata.get(IdAuthCommonConstants.IDENTITY_INFO) != null) {
                    kycAuthResponseDTO = kycFacade.processKycAuth(authRequestDTO, authResponseDTO, partnerId, oidcClientId, metadata);
                }
                return kycAuthResponseDTO;
            } catch (IDDataValidationException e) {
                mosipLogger.error(IdAuthCommonConstants.SESSION_ID, this.getClass().getSimpleName(), "processKycAuth",
                        e.getErrorTexts().isEmpty() ? "" : e.getErrorText());

                auditHelper.auditExceptionForAuthRequestedModules(AuditEvents.KYC_REQUEST_RESPONSE, authRequestDTO, e);
                IdaRequestResponsConsumerUtil.setIdVersionToObjectWithMetadata(requestWrapperWithMetadata, e);
                e.putMetadata(IdAuthCommonConstants.TRANSACTION_ID, authRequestDTO.getTransactionID());
                throw authTransactionHelper.createDataValidationException(authTxnBuilder, e, requestWrapperWithMetadata);
            } catch (IdAuthenticationBusinessException e) {
                mosipLogger.error(IdAuthCommonConstants.SESSION_ID, this.getClass().getSimpleName(), "processKycAuth",
                        e.getErrorTexts().isEmpty() ? "" : e.getErrorText());

                if (IdAuthenticationErrorConstants.ID_NOT_AVAILABLE.getErrorCode().equals(e.getErrorCode())) {
                    ondemandTemplateEventPublisher.notify(authRequestDTO, request.getHeader("signature"), partner, e,
                            authRequestDTO.getMetadata());
                }
                auditHelper.auditExceptionForAuthRequestedModules(AuditEvents.KYC_REQUEST_RESPONSE, authRequestDTO, e);
                IdaRequestResponsConsumerUtil.setIdVersionToObjectWithMetadata(requestWrapperWithMetadata, e);
                e.putMetadata(IdAuthCommonConstants.TRANSACTION_ID, authRequestDTO.getTransactionID());
                throw authTransactionHelper.createUnableToProcessException(authTxnBuilder, e, requestWrapperWithMetadata);
            }
        } else {
            mosipLogger.error("Technical error. HttpServletRequest is not instanceof ObjectWithMetada.");
            throw new IdAuthenticationBusinessException(IdAuthenticationErrorConstants.UNABLE_TO_PROCESS);
        }
    }
}
