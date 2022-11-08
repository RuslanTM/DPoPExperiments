package demo.dpop.experiments.controller;

import demo.dpop.experiments.model.DPoPProofRequestDto;
import demo.dpop.experiments.model.DPoPProofResponseDto;
import demo.dpop.experiments.service.DPoPService;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

@Path("/dpop")
public class DPoPExperimentsController {

    @Inject
    DPoPService dPoPService;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public DPoPProofResponseDto generateDPoP(DPoPProofRequestDto requestDto) {
        return dPoPService.generateDPoPProof(requestDto);
    }
}