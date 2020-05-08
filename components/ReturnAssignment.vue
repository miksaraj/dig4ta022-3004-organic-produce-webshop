<template>
	<div>
		<h3>Otsikko</h3>
		<p>Kootut selitykset</p>
		<!-- TODO: add :accept="filetype ? filetype : ''" to b-form-file -->
		<b-form-file
			v-model="file"
			:state="Boolean(file)"
			placeholder="Palauta vastauksesi tähän..."
			drop-placeholder="Pudota tiedosto tähän..."
		></b-form-file>
		<b-button class="btn-primary" @click="file = null">Tyhjennä</b-button>
		<!-- TODO: add submit button when we have an idea where this goes... -->
	</div>
</template>

<style scoped>
.btn {
	margin-top: 1rem;
}
</style>

<script>
export default {
	name: 'ReturnAssignment',
	data() {
		return {
			file: null
		}
	}
}
</script>
